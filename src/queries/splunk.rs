//! Splunk queries
//!
//! Holds the username and password for Splunk
use super::ip::IpDB;
use crate::user::vpnlog::VpnLog;
use crate::user::{login::Login, User};
use chrono::NaiveDateTime;
use log::{debug, info};
use rayon::prelude::*;
use regex::Regex;
use std::collections::HashMap;
use std::io::Read;
use std::net::Ipv4Addr;
use std::sync::OnceLock;
use ureq;
use url::Url;

/// Date format for the Splunk API when specifying start and end times
const DATE_FORMAT: &str = "%FT%T";
/// Buffer size of responses to queries for Sonar
const BUF_SIZE: usize = 10_000;

static GET_DUO_USER_RE: OnceLock<Regex> = OnceLock::new();
static DHCP_IP_RE: OnceLock<Regex> = OnceLock::new();
static DHCP_MAC_RE: OnceLock<Regex> = OnceLock::new();
static CISCO_IP_RE: OnceLock<Regex> = OnceLock::new();
static CISCO_USER_RE: OnceLock<Regex> = OnceLock::new();
static ISE_USER_MAC_RE: OnceLock<Regex> = OnceLock::new();
static ISE_MAC_MAC_RE: OnceLock<Regex> = OnceLock::new();

pub struct Splunk {
    url: Url,
    auth: String,
    /// GeoIP db, it is held in Splunk as Splunk creates the logins and thus holds the IpDB to pass
    /// a reference to the login serialization function
    ipinfo: IpDB,
}

impl Splunk {
    /// Checks the user and password against Splunk and returns it's self if valid
    pub fn new(username: &str, password: Option<&str>) -> Option<Self> {
        let status = ureq::get("https://TOP_SNEAKY_URL")
            .send_form(&[("username", username), ("password", password.unwrap_or(""))])
            .ok()?
            .status();

        info!("Splnuk status was {}", status);

        let url: Url = Url::parse("https://TOP_SNEAKY_URL")
            .expect("Bad Splunk URL");

        let auth = super::basic_auth(username, password);

        Some(Self {
            url,
            auth,
            ipinfo: IpDB::new(),
        })
    }

    pub fn get_duo_users(
        &self,
        time_span: &TimeSpan,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let earliest_time = format!("{}", time_span.start.format(DATE_FORMAT));
        let latest_time = format!("{}", time_span.end.format(DATE_FORMAT));

        let search = "search index=splunk_duo host=duo_api user=* | dedup user";

        info!("Querying splunk: {}", search);

        let resp = ureq::request_url("POST", &self.url)
            .set("Authorization", &self.auth)
            .send_form(&[
                ("output_mode", "json"),
                ("search", search),
                ("earliest_time", &earliest_time),
                ("latest_time", &latest_time),
            ])?;

        let mut buf = String::with_capacity(1_000_000);
        resp.into_reader()
            .read_to_string(&mut buf)
            .map_err(ureq::Error::from)?;

        info!("Got {} bytes", buf.len());

        let mut users: Vec<String> = GET_DUO_USER_RE
            .get_or_init(|| Regex::new(r#""user":"(\w+)""#).unwrap())
            .captures_iter(&buf)
            .map(|cap| cap[1].to_owned())
            .collect();

        users.par_sort();
        users.dedup();

        info!("Retrieved {} users", users.len());

        Ok(users)
    }

    pub fn get_user_logins(
        &self,
        username: &str,
        time_span: &TimeSpan,
    ) -> Result<Vec<Login>, Box<ureq::Error>> {
        let now = std::time::Instant::now();
        debug!("Starting! {:?}", now.elapsed());
        let earliest_time = format!("{}", time_span.start.format(DATE_FORMAT));
        let latest_time = format!("{}", time_span.end.format(DATE_FORMAT));

        let search = format!(
            "search index=splunk_duo host=duo_api result=* user={} | dedup _time",
            username
        );

        info!("Querying splunk: {}", search);

        let resp = ureq::request_url("POST", &self.url)
            .set("Authorization", &self.auth)
            .send_form(&[
                ("output_mode", "json"),
                ("search", &search),
                ("earliest_time", &earliest_time),
                ("latest_time", &latest_time),
            ])?;

        debug!("Starting serialization {:?}", now.elapsed());

        let mut buf = String::with_capacity(5_000_000);
        resp.into_reader()
            .read_to_string(&mut buf)
            .map_err(ureq::Error::from)?;

        info!("Got {} bytes", buf.len());

        let mut logins: Vec<Login> = buf
            .par_lines()
            .filter_map(|l| Login::new(l, &self.ipinfo))
            .collect();

        logins.par_sort();
        logins.dedup();

        info!("Finished {:?}", now.elapsed());
        info!("Got {} logins", logins.len());

        Ok(logins)
    }

    pub fn get_logins(&self, time_span: &TimeSpan) -> Result<Vec<Login>, Box<ureq::Error>> {
        let now = std::time::Instant::now();
        debug!("Starting! {:?}", now.elapsed());
        let earliest_time = format!("{}", time_span.start.format(DATE_FORMAT));
        let latest_time = format!("{}", time_span.end.format(DATE_FORMAT));

        let search = "search index=splunk_duo host=duo_api user=* result=* | dedup _time user";
        info!("Querying splunk: {}", search);

        debug!("Sending query {:?}", now.elapsed());
        let resp = ureq::request_url("POST", &self.url)
            .set("Authorization", &self.auth)
            .send_form(&[
                ("output_mode", "json"),
                ("search", search),
                ("earliest_time", &earliest_time),
                ("latest_time", &latest_time),
            ])?;

        debug!("Starting serialization {:?}", now.elapsed());

        let mut buf = String::with_capacity(150_000_000);
        resp.into_reader()
            .read_to_string(&mut buf)
            .map_err(ureq::Error::from)?;

        info!("Got {} bytes", buf.len());

        let mut logins: Vec<Login> = buf
            .par_lines()
            .filter_map(|l| Login::new(l, &self.ipinfo))
            .collect();

        logins.par_sort();
        logins.dedup();

        info!("Finished {:?}", now.elapsed());
        info!("Got {} logins", logins.len());

        Ok(logins)
    }

    pub fn match_users_and_logins(
        users: Vec<String>,
        logins: Vec<Login>,
        earliest_time: &NaiveDateTime,
    ) -> Vec<User> {
        let mut user_logins = HashMap::<String, Vec<Login>>::with_capacity(users.len());
        for user in users {
            user_logins.insert(user.to_owned(), vec![]);
        }

        for login in logins {
            if let Some(user) = user_logins.get_mut(&login.user) {
                user.push(login);
            }
        }

        let user_logins: Vec<User> = user_logins
            .into_iter()
            .map(|(user, mut logins)| {
                logins.sort();
                User::new(user, logins, earliest_time)
            })
            .collect();

        user_logins
    }

    // -------------------- Visor --------------------

    pub fn get_user_vpn(
        &self,
        username: &str,
        time_span: TimeSpan,
    ) -> Result<Vec<VpnLog>, Box<ureq::Error>> {
        let now = std::time::Instant::now();
        debug!("Starting! {:?}", now.elapsed());
        let earliest_time = format!("{}", time_span.start.format(DATE_FORMAT));
        let latest_time = format!("{}", time_span.end.format(DATE_FORMAT));

        let search = format!(
            r#"search index=splunk_network_ise Firepower-9300-ASA Calling_Station_ID=* UserName={} Class=CUVPN Acct_Status_Type="Start" OR Acct_Status_Type="Stop" | dedup _time | sort -_time"#,
            username
        );
        info!("Querying splunk: {}", search);

        debug!("Sending query {:?}", now.elapsed());
        let resp = ureq::request_url("POST", &self.url)
            .set("Authorization", &self.auth)
            .send_form(&[
                ("output_mode", "json"),
                ("search", &search),
                ("earliest_time", &earliest_time),
                ("latest_time", &latest_time),
            ])?;

        debug!("Starting serialization {:?}", now.elapsed());

        let mut buf = String::with_capacity(BUF_SIZE);
        resp.into_reader()
            .read_to_string(&mut buf)
            .map_err(ureq::Error::from)?;

        info!("Got {} bytes", buf.len());

        let mut vpn_logs: Vec<VpnLog> = buf
            .par_lines()
            .filter_map(|l| VpnLog::new(l, &self.ipinfo))
            .collect();

        vpn_logs.par_sort();
        vpn_logs.dedup();

        info!("Finished {:?}", now.elapsed());
        info!("Got {} logins", vpn_logs.len());

        Ok(vpn_logs)
    }

    pub fn correlate_vpn_logs(vpn_logs: &mut Vec<VpnLog>) {
        for i in 1..vpn_logs.len() {
            if vpn_logs[i - 1].correlates(&vpn_logs[i]) {
                vpn_logs[i - 1].correlate_prev = true;
            }
        }
    }

    // -------------------- Sonar --------------------

    pub fn get_ip_from_mac(&self, mac: &str) -> Option<Ipv4Addr> {
        let now = std::time::Instant::now();
        debug!("Starting! {:?}", now.elapsed());
        info!("Getting IP for {}", mac);
        let time_span: TimeSpan = chrono::Duration::hours(24).into();
        let earliest_time = format!("{}", time_span.start.format(DATE_FORMAT));
        let latest_time = format!("{}", time_span.end.format(DATE_FORMAT));

        // It's faster to search Splunk without dest_mac={}
        let search = format!("search index=splunk_network_dhcp {}", mac);
        info!("Querying splunk: {}", search);

        debug!("Sending query {:?}", now.elapsed());
        let resp = ureq::request_url("POST", &self.url)
            .set("Authorization", &self.auth)
            .send_form(&[
                ("output_mode", "json"),
                ("search", &search),
                ("earliest_time", &earliest_time),
                ("latest_time", &latest_time),
            ])
            .ok()?;

        debug!("Starting serialization {:?}", now.elapsed());

        let mut buf = String::with_capacity(BUF_SIZE);
        resp.into_reader()
            .take(BUF_SIZE as u64)
            .read_to_string(&mut buf)
            .ok()?;

        info!("Got {} bytes", buf.len());

        DHCP_IP_RE
            .get_or_init(|| Regex::new(r#"on ([0-9.]+) to"#).unwrap())
            .captures(&buf)
            .and_then(|cap| cap[1].parse().ok())
    }

    pub fn get_ip_from_user(&self, user: &str) -> Option<Ipv4Addr> {
        let now = std::time::Instant::now();
        debug!("Starting! {:?}", now.elapsed());
        info!("Getting IP for {}", user);
        let time_span: TimeSpan = chrono::Duration::hours(24).into();
        let earliest_time = format!("{}", time_span.start.format(DATE_FORMAT));
        let latest_time = format!("{}", time_span.end.format(DATE_FORMAT));

        // It's faster to search Splunk without dest_mac={}
        let search = format!("search index=splunk_network_cisco Username=* {}", user);
        info!("Querying splunk: {}", search);

        debug!("Sending query {:?}", now.elapsed());
        let resp = ureq::request_url("POST", &self.url)
            .set("Authorization", &self.auth)
            .send_form(&[
                ("output_mode", "json"),
                ("search", &search),
                ("earliest_time", &earliest_time),
                ("latest_time", &latest_time),
            ])
            .ok()?;

        debug!("Starting serialization {:?}", now.elapsed());

        let mut buf = String::with_capacity(BUF_SIZE);
        resp.into_reader()
            .take(BUF_SIZE as u64)
            .read_to_string(&mut buf)
            .ok()?;

        info!("Got {} bytes", buf.len());

        CISCO_IP_RE
            .get_or_init(|| Regex::new(r#"IP (?:= |<)([0-9.]+)"#).unwrap())
            .captures(&buf)
            .and_then(|cap| cap[1].parse().ok())
    }

    pub fn get_user_from_ip(&self, ip: Ipv4Addr) -> Option<String> {
        let now = std::time::Instant::now();
        debug!("Starting! {:?}", now.elapsed());
        let time_span: TimeSpan = chrono::Duration::hours(24).into();
        let earliest_time = format!("{}", time_span.start.format(DATE_FORMAT));
        let latest_time = format!("{}", time_span.end.format(DATE_FORMAT));

        // It's faster to search Splunk without dest_mac={}
        let search = format!("search index=splunk_network_cisco {}", ip);
        info!("Querying splunk: {}", search);

        debug!("Sending query {:?}", now.elapsed());
        let resp = ureq::request_url("POST", &self.url)
            .set("Authorization", &self.auth)
            .send_form(&[
                ("output_mode", "json"),
                ("search", &search),
                ("earliest_time", &earliest_time),
                ("latest_time", &latest_time),
            ])
            .ok()?;

        debug!("Starting serialization {:?}", now.elapsed());

        let mut buf = String::with_capacity(BUF_SIZE);
        resp.into_reader()
            .take(BUF_SIZE as u64)
            .read_to_string(&mut buf)
            .ok()?;

        info!("Got {} bytes", buf.len());

        CISCO_USER_RE
            .get_or_init(|| Regex::new(r#"(?:user = |Username = |User <)(\w+)"#).unwrap())
            .captures(&buf)
            .and_then(|cap| {
                let user = cap[1].to_string();
                if Self::is_user(&user) {
                    Some(user)
                } else {
                    None
                }
            })
    }

    pub fn get_mac_from_ip(&self, ip: Ipv4Addr) -> Option<Vec<String>> {
        let now = std::time::Instant::now();
        debug!("Starting! {:?}", now.elapsed());
        info!("Getting MAC for {}", ip);
        let time_span: TimeSpan = chrono::Duration::hours(24).into();
        let earliest_time = format!("{}", time_span.start.format(DATE_FORMAT));
        let latest_time = format!("{}", time_span.end.format(DATE_FORMAT));

        // It's faster to search Splunk without dest_ip={}
        let search = format!("search index=splunk_network_dhcp {}", ip);
        info!("Querying splunk: {}", search);

        debug!("Sending query {:?}", now.elapsed());
        let resp = ureq::request_url("POST", &self.url)
            .set("Authorization", &self.auth)
            .send_form(&[
                ("output_mode", "json"),
                ("search", &search),
                ("earliest_time", &earliest_time),
                ("latest_time", &latest_time),
            ])
            .ok()?;

        debug!("Starting serialization {:?}", now.elapsed());

        let mut buf = String::with_capacity(BUF_SIZE);
        resp.into_reader()
            .take(BUF_SIZE as u64)
            .read_to_string(&mut buf)
            .ok()?;

        info!("Got {} bytes", buf.len());

        DHCP_MAC_RE
            .get_or_init(|| Regex::new(r#"to ([0-9a-f:]+)"#).unwrap())
            .captures(&buf)
            .map(|cap| {
                cap.iter()
                    .filter_map(|c| {
                        if let Some(c) = c {
                            if Self::is_mac(c.as_str()) {
                                return Some(c.as_str().to_string());
                            }
                        }
                        None
                    })
                    .collect::<Vec<String>>()
            })
    }

    pub fn get_mac_from_user(&self, user: &str) -> Option<Vec<String>> {
        let now = std::time::Instant::now();
        debug!("Starting! {:?}", now.elapsed());
        info!("Getting MAC for {}", user);
        let time_span: TimeSpan = chrono::Duration::hours(24).into();
        let earliest_time = format!("{}", time_span.start.format(DATE_FORMAT));
        let latest_time = format!("{}", time_span.end.format(DATE_FORMAT));

        // It's faster to search Splunk without dest_ip={}
        let search = format!("search index=splunk_network_ise {}", user);
        info!("Querying splunk: {}", search);

        debug!("Sending query {:?}", now.elapsed());
        let resp = ureq::request_url("POST", &self.url)
            .set("Authorization", &self.auth)
            .send_form(&[
                ("output_mode", "json"),
                ("search", &search),
                ("earliest_time", &earliest_time),
                ("latest_time", &latest_time),
            ])
            .ok()?;

        debug!("Starting serialization {:?}", now.elapsed());

        let mut buf = String::with_capacity(BUF_SIZE);
        resp.into_reader()
            .take(BUF_SIZE as u64)
            .read_to_string(&mut buf)
            .ok()?;

        info!("Got {} bytes", buf.len());

        ISE_USER_MAC_RE
            .get_or_init(|| Regex::new(r#"to ([0-9a-f:]+)"#).unwrap())
            .captures(&buf)
            .map(|cap| {
                cap.iter()
                    .filter_map(|c| {
                        if let Some(c) = c {
                            let mac = c.as_str().replace('-', ":");
                            if Self::is_mac(&mac) {
                                return Some(mac);
                            }
                        }
                        None
                    })
                    .collect::<Vec<String>>()
            })
    }

    pub fn get_user_from_mac(&self, mac: &str) -> Option<String> {
        let now = std::time::Instant::now();
        debug!("Starting! {:?}", now.elapsed());
        info!("Getting MAC for {}", mac);
        let time_span: TimeSpan = chrono::Duration::hours(24).into();
        let earliest_time = format!("{}", time_span.start.format(DATE_FORMAT));
        let latest_time = format!("{}", time_span.end.format(DATE_FORMAT));

        // It's faster to search Splunk without dest_ip={}
        let search = format!("search index=splunk_network_ise {}", mac);
        info!("Querying splunk: {}", search);

        debug!("Sending query {:?}", now.elapsed());
        let resp = ureq::request_url("POST", &self.url)
            .set("Authorization", &self.auth)
            .send_form(&[
                ("output_mode", "json"),
                ("search", &search),
                ("earliest_time", &earliest_time),
                ("latest_time", &latest_time),
            ])
            .ok()?;

        debug!("Starting serialization {:?}", now.elapsed());

        let mut buf = String::with_capacity(BUF_SIZE);
        resp.into_reader()
            .take(BUF_SIZE as u64)
            .read_to_string(&mut buf)
            .ok()?;

        info!("Got {} bytes", buf.len());

        ISE_MAC_MAC_RE
            .get_or_init(|| Regex::new(r#"to ([0-9a-f:]+)"#).unwrap())
            .captures(&buf)
            .and_then(|cap| {
                let mac = cap[1].to_string();
                if Self::is_mac(&mac) {
                    Some(mac)
                } else {
                    None
                }
            })
    }

    pub fn is_mac(mac: &str) -> bool {
        mac.len() == 17
            && mac
                .split(':')
                .all(|byte| byte.len() == 2 && byte.chars().all(|c| c.is_ascii_hexdigit()))
    }

    pub fn is_user(user: &str) -> bool {
        user.len() >= 2 && user.len() < 20 && user.chars().all(|c| c.is_ascii_alphanumeric())
    }
}

const TIME_FMT: &str = "%H:%M";

pub struct TimeSpan {
    pub start: NaiveDateTime,
    pub end: NaiveDateTime,
}

impl TimeSpan {
    pub fn from(dates: (chrono::NaiveDate, chrono::NaiveDate), times: &(String, String)) -> Self {
        let start_time: chrono::NaiveTime =
            chrono::NaiveTime::parse_from_str(&times.0, TIME_FMT).expect("Bad start time format");
        let end_time: chrono::NaiveTime =
            chrono::NaiveTime::parse_from_str(&times.1, TIME_FMT).expect("Bad end time format");
        let start = NaiveDateTime::new(dates.0, start_time);
        let end = NaiveDateTime::new(dates.1, end_time);
        TimeSpan { start, end }
    }
}

impl From<chrono::Duration> for TimeSpan {
    fn from(dur: chrono::Duration) -> Self {
        let end = chrono::Local::now().naive_local();
        let start = end - dur;
        Self { start, end }
    }
}
