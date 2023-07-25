//! Connective glue between the UI and other modules
//!
//! Hold all the weird bits that don't feel right staying in the UI but don't belong in any other
//! module.  This is where the main logic lööps of the apps are.
use crate::{
    queries::{
        hdtools::HDTools,
        ip::IpThreat,
        osiris,
        splunk::{Splunk, TimeSpan},
        Queries,
    },
    storage::Storage,
    user::{login::Login, vpnlog::VpnLog, User},
};
use chrono::{Duration, NaiveDate};
use log::info;
use std::thread;
use std::{net::Ipv4Addr, sync::Mutex};
use std::{
    sync::{Arc, RwLock},
    thread::JoinHandle,
};

pub struct Store {
    storage: Arc<Mutex<Storage>>,
    queries: Queries,
    /// Range 0..=1 that keeps track of how many users have been processed for Duplex
    progress: Arc<RwLock<f32>>,
    analyst_name: String,
    /// Remembers failed IPs to avoid repeated network quering.  This is held in the store as putting
    /// inside ipq, where it should be, would mean wrapping it in a RwLock or Mutex, I'm lazy and
    /// didn't want to do this
    failed_ips: RwLock<Vec<Ipv4Addr>>,
}

impl Store {
    pub fn new(
        splunk: Splunk,
        hdtools: Option<HDTools>,
        storage: Storage,
        analyst_name: String,
    ) -> Self {
        let storage = Arc::new(Mutex::new(storage));
        let progress = Arc::new(RwLock::new(0.0));
        Self {
            storage,
            progress,
            queries: Queries::new(splunk, hdtools),
            analyst_name,
            failed_ips: RwLock::new(Vec::default()),
        }
    }

    // -------------------- Duplex --------------------

    /// Main lööp of Duplex.  This pulls all users and logs from Splunk and performs three rounds
    /// of vibe checks.  The first only keeps users with fraud, failures, impossible travel, or
    /// device management portal access.  The second round removes all users created in the past 6
    /// months and all users with activity only from their home state.  The third round will check
    /// every IP for alternate locations by polling other databases, determining which IP is closer
    /// to previous logs or the user's home, and then re-runs the first vibe check with the updated
    /// IP locations.
    pub fn run_duplex(
        &self,
        user_range: TimeSpan,
        history_range: TimeSpan,
    ) -> JoinHandle<Vec<User>> {
        info!("Starting initial run");
        {
            if let Ok(mut prog) = self.progress.write() {
                *prog = 0.0;
            }
        }
        let hdtools = self.queries.hdtools.as_ref().map(Arc::clone);
        let ipq = Arc::clone(&self.queries.ipq);
        let splunk = Arc::clone(&self.queries.splunk);
        let storage = Arc::clone(&self.storage);
        let progress = Arc::clone(&self.progress);
        thread::spawn::<_, Vec<User>>(move || {
            let user_list = match splunk.get_duo_users(&user_range) {
                Ok(users) => users,
                Err(_) => return vec![],
            };
            let login_list = match splunk.get_logins(&history_range) {
                Ok(logins) => logins,
                Err(_) => return vec![],
            };
            let mut users = crate::queries::splunk::Splunk::match_users_and_logins(
                user_list,
                login_list,
                &user_range.start,
            );

            info!("Performing first vibe check");
            {
                // Brackets ensures storage is dropped
                let storage = storage.lock().expect("Couldn't get storage lock");
                users = users
                    .into_iter()
                    .filter_map(|mut user| {
                        if !user.first_vibe_check() && !storage.investigated(&user.name) {
                            Some(user)
                        } else {
                            None
                        }
                    })
                    .collect();
            }

            let count = users.len() as f32;

            if let Some(hdtools) = hdtools.as_ref() {
                info!("Performing second vibe check for {} users", count);
                let storage = storage.lock().expect("Couldn't get storage lock");
                users = users
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, mut user)| {
                        {
                            if let Ok(mut prog) = progress.write() {
                                *prog = (i + 1) as f32 / count / 2.0;
                            }
                        }

                        if let Some((creation_date, location)) = storage.get_hdtools(&user.name) {
                            user.location = location;
                            user.creation_date = Some(creation_date);
                        } else if let Some((creation_date, location)) = hdtools.get_info(&user.name)
                        {
                            user.location = location.to_owned();
                            user.creation_date = Some(creation_date.to_owned());

                            storage.add_hdtools(&user.name, (creation_date, location));
                        }

                        if !user.second_vibe_check() {
                            info!("{} failed second vibe check", user.name);
                            Some(user)
                        } else {
                            None
                        }
                    })
                    .collect();
            }

            let count = users.len() as f32;

            info!("Performing third vibe check for {} users", count);
            {
                if let Ok(storage) = storage.lock() {
                    users = users
                        .into_iter()
                        .enumerate()
                        .filter_map(|(i, mut user)| {
                            {
                                if let Ok(mut prog) = progress.write() {
                                    *prog = (i + 1 + count as usize / 2) as f32 / count;
                                }
                            }

                            for i in 0..user.checked_login_count {
                                let login = &user.logins[i];
                                if login.is_priv_ip() || login.is_vpn_ip() {
                                    continue;
                                }
                                if let Some(ip) = login.ip {
                                    if let Some(ipinfo) = storage.get_ipinfo(ip).or_else(|| {
                                        let ipinfo = ipq.get_info(ip);
                                        if let Some(ipinfo) = &ipinfo {
                                            storage.add_ipinfo(ip, ipinfo.clone());
                                        }
                                        ipinfo
                                    }) {
                                        // Updates login location if it correlates better with
                                        // surrounding logs
                                        if user.closer_to(&ipinfo, i) {
                                            info!("Updating log with ip {} for {}", ip, user.name);
                                            user.logins[i].location =
                                                Some((ipinfo.loc.lat, ipinfo.loc.lon));
                                            user.logins[i].country = Some(ipinfo.country);
                                            user.logins[i].state = Some(ipinfo.region);
                                            user.logins[i].city = Some(ipinfo.city);
                                        }
                                    }
                                }
                            }

                            if !user.first_vibe_check() && !storage.investigated(&user.name) {
                                Some(user)
                            } else {
                                info!("{} is no longer funky", user.name);
                                None
                            }
                        })
                        .collect();
                }
            }

            if count == users.len() as f32 {
                info!("Third vibe check did not remove any users");
            }

            users.sort();

            info!("Finished initial run with {} users", users.len());
            users
        })
    }

    /// Used by Duplex to query more logs for a specific user
    pub fn more_info(&self, name: String, days: i64) -> JoinHandle<Option<Vec<Login>>> {
        let splunk = Arc::clone(&self.queries.splunk);
        let days = days;
        thread::spawn(move || {
            let timespan = Duration::days(days).into();
            splunk.get_user_logins(&name, &timespan).ok()
        })
    }

    /// Returns the progress of [run_duplex()](Self::run_duplex())
    pub fn progress(&self) -> f32 {
        let count = self
            .progress
            .read()
            .expect("Failed to get storage read lock");
        *count
    }

    pub fn mark_investigated(&self, user: String, mark: bool) {
        let storage = self.storage.lock().expect("Failed to get storage lock");
        storage.mark_investigated(user, mark);
    }

    pub fn analyst_name(&self) -> &str {
        &self.analyst_name
    }

    /// Returns true if HDTools queries are available to use
    pub fn has_hdtools(&self) -> bool {
        self.queries.hdtools.is_some()
    }

    pub fn get_ipthreat(&self, ip: Ipv4Addr) -> Option<IpThreat> {
        let storage = self.storage.lock().expect("Failed to get storage lock");
        let ipthreat = storage.get_threat(ip);
        drop(storage);

        if ipthreat.is_some() {
            return ipthreat;
        }

        if self
            .failed_ips
            .read()
            .expect("Failed to get failed_ips read lock")
            .contains(&ip)
        {
            return None;
        }

        if let Some(ipthreat) = self.queries.ipq.get_threat(ip) {
            let storage = self.storage.lock().expect("Failed to get storage lock");
            storage.add_threat(ip, ipthreat.clone());
            Some(ipthreat)
        } else {
            self.failed_ips
                .write()
                .expect("Failed to get failed_ips write lock")
                .push(ip);
            None
        }
    }

    // -------------------- Simplex --------------------

    /// Main lööp of Simplex.  This will query the user's logs from Splunk and fetch their HDTools
    /// information, if available.
    pub fn run_simplex(&self, user: String, days: i64) -> JoinHandle<Option<User>> {
        info!("Running Simplex");
        let splunk = Arc::clone(&self.queries.splunk);
        let hdtools = self.queries.hdtools.as_ref().map(Arc::clone);
        let storage = Arc::clone(&self.storage);
        thread::spawn(move || {
            let timespan: TimeSpan = Duration::days(days).into();
            let logins = splunk.get_user_logins(user.as_str(), &timespan).ok()?;
            let mut user = User::new(
                user,
                logins,
                &(chrono::Local::now().naive_local() - Duration::days(days)),
            );

            let storage = storage.lock().expect("Failed to get storage lock");
            if let Some((creation_date, location)) = storage.get_hdtools(&user.name) {
                user.creation_date = Some(creation_date);
                user.location = location;
            }
            if user.creation_date.is_none() || user.location.is_none() {
                if let Some(hdtool) = hdtools {
                    if let Some((creation_date, location)) = hdtool.get_info(&user.name) {
                        storage.add_hdtools(&user.name, (creation_date, location.to_owned()));
                        drop(storage);

                        user.creation_date = Some(creation_date);
                        user.location = location;
                    }
                }
            }
            Some(user)
        })
    }

    // -------------------- Visor --------------------

    /// Main lööp of Visor.  Will pull VPN logs from Splunk and try to correlate
    pub fn run_visor(&self, user: String) -> JoinHandle<Option<Vec<VpnLog>>> {
        info!("Running Visor");
        let splunk = Arc::clone(&self.queries.splunk);
        thread::spawn(move || {
            let timespan: TimeSpan = Duration::days(7).into();
            let mut vpn_logs = splunk.get_user_vpn(user.as_str(), timespan).ok();

            if let Some(ref mut vpn_logs) = vpn_logs {
                Splunk::correlate_vpn_logs(vpn_logs);
            }

            vpn_logs
        })
    }

    // -------------------- Sonar --------------------

    /// Main lööp of Sonar.  Runs two rounds of querying Splunk using IP/MAC/user to find more
    /// IPs/MACs/users.  Takes forever which is why I made the UI update as more things are found.
    pub fn run_sonar(&self, lookup: String, details: &Arc<RwLock<crate::app::sonar::Details>>) {
        info!("Running Sonar");
        let details = Arc::clone(details);
        let splunk = Arc::clone(&self.queries.splunk);
        thread::spawn(move || {
            {
                let mut details = details.write().expect("Failed to get details write lock");
                details.running = true;
            }

            let mut ips: Vec<Ipv4Addr> = vec![];
            let mut macs: Vec<String> = vec![];
            let mut user: Option<String> = None;

            if crate::store::Splunk::is_mac(&lookup) {
                let mut details = details.write().expect("Failed to get details write lock");
                details.macs.push(lookup.to_owned());
                macs.push(lookup);
            } else if let Ok(ip_parse) = lookup.parse::<Ipv4Addr>() {
                let mut details = details.write().expect("Failed to get details write lock");
                details.ips.push(ip_parse);
                ips.push(ip_parse);
            } else if crate::store::Splunk::is_user(&lookup) {
                let mut details = details.write().expect("Failed to get details write lock");
                details.user = Some(lookup.to_owned());
                user = Some(lookup);
            } else {
                let mut details = details.write().expect("Failed to get details write lock");
                details.running = false;
                return;
            }

            // Run twice to grab everything
            for _ in 0..2 {
                // Find IPs
                for mac in &macs {
                    info!("Looking up IP from MAC");
                    if let Some(ip) = splunk.get_ip_from_mac(mac) {
                        if ips.contains(&ip) {
                            continue;
                        }
                        ips.push(ip);
                        let mut details =
                            details.write().expect("Failed to get details write lock");
                        details.ips.push(ip);
                    }
                }
                if let Some(user) = &user {
                    info!("Looking up IP from user");
                    if let Some(ip) = splunk.get_ip_from_user(user) {
                        if ips.contains(&ip) {
                            continue;
                        }
                        ips.push(ip);
                        let mut details =
                            details.write().expect("Failed to get details write lock");
                        details.ips.push(ip.to_owned());
                    }
                }

                // Find MACs
                for ip in &ips {
                    info!("Looking up MAC from IP");
                    if let Some(found_macs) = splunk.get_mac_from_ip(*ip) {
                        for mac in found_macs {
                            if macs.contains(&mac) {
                                continue;
                            }
                            macs.push(mac.to_owned());
                            let mut details =
                                details.write().expect("Failed to get details write lock");
                            details.macs.push(mac);
                        }
                    }
                }
                if let Some(user) = &user {
                    info!("Looking up MAC from user");
                    if let Some(found_macs) = splunk.get_mac_from_user(user) {
                        for mac in found_macs {
                            if macs.contains(&mac) {
                                continue;
                            }
                            macs.push(mac.to_owned());
                            let mut details =
                                details.write().expect("Failed to get details write lock");
                            details.macs.push(mac);
                        }
                    }
                }

                // Find user
                if user.is_none() {
                    for ip in &ips {
                        info!("Looking up user from IP");
                        if let Some(user) = splunk.get_user_from_ip(*ip) {
                            let mut details =
                                details.write().expect("Failed to get details write lock");
                            details.user = Some(user);
                        }
                    }
                    for mac in &macs {
                        info!("Looking up user from MAC");
                        if let Some(user) = splunk.get_user_from_mac(mac) {
                            let mut details =
                                details.write().expect("Failed to get details write lock");
                            details.user = Some(user);
                        }
                    }
                }
            }

            {
                let mut details = details.write().expect("Failed to get details write lock");
                details.running = false;
            }
        });
    }

    // -------------------- Zeppelin --------------------

    /// Pulls date's [Data](osiris::Data) from Osiris
    pub fn run_zeppelin(&self, date: NaiveDate) -> JoinHandle<Option<osiris::Data>> {
        let osiris = Arc::clone(&self.queries.osiris);
        thread::spawn(move || osiris.get_date(date))
    }

    /// Sends data for a date to Osiris
    pub fn post_osiris(&self, date: NaiveDate, data: osiris::Data) -> JoinHandle<Option<()>> {
        let osiris = Arc::clone(&self.queries.osiris);
        thread::spawn(move || osiris.post_date(date, data))
    }

    /// Pulls data for a date range and writes it to CSV file.  No, I do not apologize for using
    /// `.join(", ")` instead of finding a better way to do it.
    pub fn save_report(&self, file: String, range: (NaiveDate, NaiveDate)) -> JoinHandle<()> {
        let osiris = Arc::clone(&self.queries.osiris);
        thread::spawn(move || {
            info!("Saving Osiris to {}", file);
            let data = match osiris.get() {
                Some(data) => data,
                None => return,
            };

            info!("Got {} lines of data", data.len());

            let mut types = vec!["time".to_owned()];

            for (_, data) in &data {
                for (inv, _) in &data.investigations {
                    if !types.contains(inv) {
                        types.push(inv.to_owned());
                    }
                }
                for (inc, _) in &data.incidents {
                    if !types.contains(inc) {
                        types.push(inc.to_owned());
                    }
                }
            }

            let mut output: Vec<Vec<String>> = Vec::with_capacity(data.len());
            output.push(types.to_owned());

            for (time, data) in data {
                let mut row = Vec::with_capacity(types.len());
                row.push(time);

                't: for kind in types.iter().skip(1) {
                    for (inv, c) in &data.investigations {
                        if kind == inv {
                            row.push(format!("{}", c));
                            continue 't;
                        }
                    }
                    for (inc, c) in &data.incidents {
                        if kind == inc {
                            row.push(format!("{}", c));
                            continue 't;
                        }
                    }

                    row.push(String::default());
                }

                output.push(row);
            }

            let output: Vec<String> = output.into_iter().map(|r| r.join(", ")).collect();

            if std::fs::write(file, output.join("\n")).is_ok() {
                info!("Wrote to file");
            } else {
                log::error!("Failed to write to file");
            };
        })
    }
}
