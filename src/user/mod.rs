//! Structures and methods to represent a user
pub mod login;
mod test;
pub mod vpnlog;
use crate::queries::ip::IpInfo;

use self::login::{FlagReason, Integration, Reason};
use self::login::{Login, LoginResult};
use chrono::{Duration, NaiveDateTime};
use log::info;
use serde::{Deserialize, Serialize};

const MEAN_EARTH_RADIUS: f32 = 6_371_008.8;
const EARTH_CIRCUMFERENCE: f32 = 40_030.23; // km
/// The maximum time it could take to travel one side the earth to the other at 1000 kph which would still be
/// considered impossible travel.  This is used to determine how far back to check user logs.
const MAX_IMPOSSIBLE_TRAVEL_TIME: i64 = (EARTH_CIRCUMFERENCE / 2_f32 / 1_000_f32 * 60_f32) as i64; // min

const STATE_ABBREVIATIONS: [(&str, &str); 50] = [
    ("Alabama", "AL"),
    ("Alaska", "AK"),
    ("Arizona", "AZ"),
    ("Arkansas", "AR"),
    ("California", "CA"),
    ("Colorado", "CO"),
    ("Connecticut", "CT"),
    ("Delaware", "DE"),
    ("Florida", "FL"),
    ("Georgia", "GA"),
    ("Hawaii", "HI"),
    ("Idaho", "ID"),
    ("Illinois", "IL"),
    ("Indiana", "IN"),
    ("Iowa", "IA"),
    ("Kansas", "KS"),
    ("Kentucky", "KY"),
    ("Louisiana", "LA"),
    ("Maine", "ME"),
    ("Maryland", "MD"),
    ("Massachusetts", "MA"),
    ("Michigan", "MI"),
    ("Minnesota", "MN"),
    ("Mississippi", "MS"),
    ("Missouri", "MO"),
    ("Montana", "MT"),
    ("Nebraska", "NE"),
    ("Nevada", "NV"),
    ("New Hampshire", "NH"),
    ("New Jersey", "NJ"),
    ("New Mexico", "NM"),
    ("New York", "NY"),
    ("North Carolina", "NC"),
    ("North Dakota", "ND"),
    ("Ohio", "OH"),
    ("Oklahoma", "OK"),
    ("Oregon", "OR"),
    ("Pennsylvania", "PA"),
    ("Rhode Island", "RI"),
    ("South Carolina", "SC"),
    ("South Dakota", "SD"),
    ("Tennessee", "TN"),
    ("Texas", "TX"),
    ("Utah", "UT"),
    ("Vermont", "VT"),
    ("Virginia", "VA"),
    ("Washington", "WA"),
    ("West Virginia", "WV"),
    ("Wisconsin", "WI"),
    ("Wyoming", "WY"),
];

/// Represents a person with dreams, ambition, *desires*, and shortcomings
#[derive(Debug, PartialEq)]
pub struct User {
    pub name: String,
    pub logins: Vec<Login>,
    /// Number of logins that are vibe checked
    pub checked_login_count: usize,
    /// Why the user failed the vibe checks
    pub reasons: Vec<FlagReason>,
    pub score: usize,
    pub location: Option<Location>,
    pub creation_date: Option<NaiveDateTime>,
    pub investigated: bool,
}

impl PartialOrd for User {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match other.fraud().partial_cmp(&self.fraud()) {
            Some(std::cmp::Ordering::Less) => Some(std::cmp::Ordering::Less),
            Some(std::cmp::Ordering::Equal) => other.score.partial_cmp(&self.score),
            Some(std::cmp::Ordering::Greater) => Some(std::cmp::Ordering::Greater),
            None => None,
        }
    }
}

impl Eq for User {}

impl Ord for User {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.score.cmp(&self.score)
    }
}

impl User {
    pub fn new(name: String, logins: Vec<Login>, earliest: &NaiveDateTime) -> Self {
        let checked_login_count = logins
            .iter()
            .take_while(|l| l.time >= *earliest - Duration::minutes(MAX_IMPOSSIBLE_TRAVEL_TIME))
            .count();

        User {
            name,
            logins,
            checked_login_count,
            reasons: Vec::with_capacity(4),
            score: 0,
            location: None,
            creation_date: None,
            investigated: false,
        }
    }

    pub fn first_vibe_check(&mut self) -> bool {
        if self.checked_login_count == 0 || self.logins.is_empty() {
            return true;
        }

        // Reset on subsequent run
        if self.score != 0 {
            self.score = 0;
            self.reasons.clear();
            for login in &mut self.logins {
                login.flag_reasons.clear();
            }
        }

        // PERFECT history passes the vibe check
        if !self
            .logins
            .iter()
            .take(self.checked_login_count)
            .any(|l| l.result != LoginResult::Success)
        {
            return true;
        }

        // Activity only from SC || NC passes
        if self.in_state() {
            info!("{} is in state - ignored", self.name);
            return true;
        }

        let failures = self.failures();
        if failures > 0 {
            self.reasons.push(FlagReason::Failure);
        }

        let fraud = self.flag_fraud();
        if fraud > 0 {
            self.reasons.push(FlagReason::Fraud);
        }

        if self.impossible_travel_precheck() {
            let travel = self.impossible_travel();
            if travel > 0 {
                self.score += travel;
                self.reasons.push(FlagReason::Travel);
            }
        }

        let dmp = self.flag_dmp();
        if dmp > 0 {
            self.reasons.push(FlagReason::Dmp);
        }

        self.score = self
            .score
            .saturating_add(failures)
            .saturating_add(fraud.saturating_mul(20))
            .saturating_add(dmp.saturating_mul(2));

        self.reasons.is_empty()
    }

    pub fn second_vibe_check(&self) -> bool {
        if self.location.is_none() || self.creation_date.is_none() || self.fraud() != 0 {
            return false;
        }

        let creation_date = self
            .creation_date
            .expect("Internal error - user has no creation date");

        let latest_log = &self.logins[0];

        // If user has been created in the past 6 months
        if latest_log.time - chrono::Duration::days(6 * 30) < creation_date
            && self
                .logins
                .iter()
                .take(self.checked_login_count)
                .any(|l| l.reason == Reason::DenyUnenrolledUser)
        {
            info!("{} was created in the past 6 months", self.name);
            return true;
        }

        // Pass if activity is from home state
        if self
            .logins
            .iter()
            .take(self.checked_login_count)
            .filter(|l| !l.is_vpn_ip() && l.state.is_some())
            .all(|l| self.same_state(l.state.as_ref().expect("Failed to get state from login")))
        {
            info!("{}'s activity is from home state", self.name);
            return true;
        }

        false
    }

    pub fn failures(&self) -> usize {
        let mut failures = 0;
        'f: for i in (0..self.checked_login_count).rev() {
            let login = &self.logins[i];
            if login.result != LoginResult::Failure {
                continue;
            }

            for i in (0..i).rev() {
                let later_login = &self.logins[i];
                if later_login.result != LoginResult::Success {
                    continue;
                }

                let time_diff = later_login.time - login.time;
                if time_diff <= Duration::minutes(30)
                    && login.integration == later_login.integration
                    && login.ip == later_login.ip
                {
                    continue 'f;
                }
            }
            failures += 1;
        }
        failures
    }

    pub fn flag_fraud(&mut self) -> usize {
        let mut count = 0;
        for login in &mut self.logins.iter_mut().take(self.checked_login_count) {
            if login.result == LoginResult::Fraud {
                login.flag_reasons.push(FlagReason::Fraud);
                count += 1;
            }
        }
        count
    }

    pub fn fraud(&self) -> usize {
        self.logins
            .iter()
            .take(self.checked_login_count)
            .filter(|l| l.result == LoginResult::Fraud)
            .count()
    }

    pub fn flag_dmp(&mut self) -> usize {
        let mut count = 0;
        for login in &mut self.logins.iter_mut().take(self.checked_login_count) {
            if login.integration == Integration::Dmp && login.result == LoginResult::Failure {
                login.flag_reasons.push(FlagReason::Dmp);
                count += 1;
            }
        }
        count
    }

    pub fn in_state(&self) -> bool {
        let mut states: Vec<&String> = vec![];

        self.logins
            .iter()
            .take(self.checked_login_count)
            .filter_map(|l| {
                if !l.is_vpn_ip() {
                    l.state.as_ref()
                } else {
                    None
                }
            })
            .for_each(|s| {
                if !states.contains(&s) {
                    states.push(s)
                }
            });

        let sc = "South Carolina".to_owned();
        let nc = "North Carolina".to_owned();
        let ga = "Georgia".to_owned();

        if states.len() == 1 && (*states[0] == sc || *states[0] == nc) {
            return true;
        }
        if states.len() == 2 {
            if states.contains(&&sc) && states.contains(&&nc) {
                return true;
            }
            if states.contains(&&sc) && states.contains(&&ga) {
                return true;
            }
        }

        false
    }

    pub fn impossible_travel_precheck(&self) -> bool {
        let (mut states, mut countries): (Vec<&String>, Vec<&String>) = self
            .logins
            .iter()
            .take(self.checked_login_count)
            .filter(|l| !l.is_vpn_ip() && l.state.is_some() && l.country.is_some())
            .map(|l| {
                (
                    l.state.as_ref().expect("Login has no state"),
                    l.country.as_ref().expect("Login has no country"),
                )
            })
            .unzip();

        states.dedup();
        countries.dedup();

        if countries.len() > 1 {
            return true;
        }

        if states.len() < 2 {
            return false;
        }

        true
    }

    pub fn impossible_travel(&mut self) -> usize {
        let mut travel = 0.0;
        let mut logins = self
            .logins
            .iter_mut()
            .take(self.checked_login_count)
            .filter(|login| {
                login.location.is_some()
                    && !login.is_vpn_ip()
                    && !login.is_priv_ip()
                    && !login.is_relay
                    && login.integration != Integration::Linux
            })
            .collect::<Vec<&mut Login>>();

        if logins.len() < 2 {
            return 0;
        }

        for i in 0..logins.len() - 1 {
            let (prev, next) = (&logins[i], &logins[i + 1]);

            let distance = Self::haversine_distance(
                &prev
                    .location
                    .expect("Internal error - login has no location"),
                &next
                    .location
                    .expect("Internal error - login has no location"),
            ) / 1000_f32; // km

            // Splunk uses the GeoIP2 and GeoLite2 databases from MaxMind, which are
            // only 82% accurate at a resolution of 250 km in the US (as of Jun 2023).
            // I have set this minimum distance to avoid false positives.
            if distance < 250_f32 {
                continue;
            }

            let time = next.time - prev.time;

            // Minutes / 60 is used to get decimal, as .num_hours() returns i64
            let kph = distance / (time.num_minutes().abs() as f32 / 60_f32);

            // The limit for impossible travel is 1000 kph to filter out the noise of
            // geoIP.  Additionally it is not too high to miss inter-country travel.
            if kph >= 1000_f32 {
                // Score is weighted such that from Clemson to Bejing in a minute is ~15 points
                // and Clemson to NY is 10 points
                travel += kph.log2().min(15_f32);
                logins[i].flag_reasons.push(FlagReason::Travel);
                logins[i + 1].flag_reasons.push(FlagReason::Travel);
            }
        }

        travel as usize
    }

    // Determin if given location is closert to surroundign logins that the current location
    pub fn closer_to(&self, ip: &IpInfo, i: usize) -> bool {
        if let Some(log_loc) = self.logins[i].location {
            // Check if location is closer to previous login
            if i != 0 {
                if let Some(prev_loc) = self.logins[i - 1].location {
                    let ip_loc = (ip.loc.lat, ip.loc.lon);
                    let cur_dist = Self::haversine_distance(&prev_loc, &log_loc);
                    let new_dist = Self::haversine_distance(&prev_loc, &ip_loc);
                    if new_dist < cur_dist {
                        return true;
                    }
                }
            }

            // Check if location is closer to user's home
            if let Some(location) = &self.location {
                if location.city == ip.city || self.same_state(&ip.region) {
                    return true;
                }
            }
        }
        false
    }

    fn haversine_distance(p1: &(f32, f32), p2: &(f32, f32)) -> f32 {
        let theta1 = p1.1.to_radians();
        let theta2 = p2.1.to_radians();
        let delta_theta = (p2.1 - p1.1).to_radians();
        let delta_lambda = (p2.0 - p1.0).to_radians();
        let a = (delta_theta / 2_f32).sin().powi(2)
            + theta1.cos() * theta2.cos() * (delta_lambda / 2_f32).sin().powi(2);
        let c = 2_f32 * a.sqrt().asin();
        MEAN_EARTH_RADIUS * c
    }

    fn same_state(&self, login_state: &str) -> bool {
        if let Some(location) = &self.location {
            if let Some(user_state) = &location.state {
                if user_state == login_state {
                    return true;
                }
                for (state, code) in STATE_ABBREVIATIONS {
                    if user_state == code && login_state == state {
                        return true;
                    }
                }
            }
        }

        false
    }
}

/// Represents a users location queried from HDTools
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Location {
    pub city: String,
    /// HDTools does not always return a state
    pub state: Option<String>,
    /// HDTools does not always return a county
    pub country: Option<String>,
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.state, &self.country) {
            (Some(s), Some(c)) => write!(f, "{}, {}, {}", self.city, s, c),
            (Some(s), None) => write!(f, "{}, {}", self.city, s),
            (None, Some(c)) => write!(f, "{}, {}", self.city, c),
            (None, None) => write!(f, "{}", self.city),
        }
    }
}
