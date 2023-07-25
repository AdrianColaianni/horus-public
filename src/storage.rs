//! Disk cache
//!
//! This stuct stores investigated users (ignored users), hdtools information, ip information
//! from ipdata.co and ipinfo.io, along with the username and analyst name.  This data should be
//! queried first before making a network query.
use chrono::{Duration, Local, TimeZone};
use dirs::cache_dir;
use log::{debug, error};
use rusqlite::Connection;
use std::{fs::File, net::Ipv4Addr};

use crate::{
    queries::{
        hdtools::HDToolsInfo,
        ip::{self, IpInfo, IpThreat},
    },
    user::Location,
};

/// Initializes the SQLite db tables
const CREATE_DB: [&str; 5] = ["
CREATE TABLE investigated_users (
    name TEXT UNIQUE, time INTEGER
);",
"CREATE TABLE hdtools (
    name TEXT UNIQUE, time INTEGER, city TEXT,
    state TEXT, country TEXT
);",
"CREATE TABLE ipthreat (
    ip INTEGER UNIQUE, is_tor INTEGER, is_icloud_relay INTEGER, is_proxy INTEGER,
    is_datacenter INTEGER, is_anonymous INTEGER, is_known_attacker INTEGER,
    is_known_abuser INTEGER, is_threat INTEGER, is_bogon INTEGER
);",
"CREATE TABLE ipinfo (
    ip INTEGER UNIQUE, hostname TEXT, city TEXT, region TEXT, country TEXT,
    lat REAL, lon REAL, org TEXT, postal TEXT, timezone TEXT
);",
"CREATE TABLE misc (
    key INTEGER UNIQUE, value TEXT
);"];

const CHECK_DB: [(&str, &[(&str, &str)]); 5] = [
    ("investigated_users", &[("name", "TEXT"), ("time", "INTEGER")]),
    ("hdtools", &[("name", "TEXT"), ("time", "INTEGER"), ("city", "TEXT"), ("state", "TEXT"), ("country", "TEXT")]),
    ("ipthreat", &[("ip", "INTEGER"), ("is_tor", "INTEGER"), ("is_icloud_relay", "INTEGER"), ("is_proxy", "INTEGER"), ("is_datacenter", "INTEGER"), ("is_anonymous", "INTEGER"), ("is_known_attacker", "INTEGER"), ("is_known_abuser", "INTEGER"), ("is_threat", "INTEGER"), ("is_bogon", "INTEGER")]),
    ("ipinfo", &[("ip", "INTEGER"), ("hostname", "TEXT"), ("city", "TEXT"), ("region", "TEXT"), ("country", "TEXT"), ("lat", "REAL"), ("lon", "REAL"), ("org", "TEXT"), ("postal", "TEXT"), ("timezone", "TEXT")]),
    ("misc", &[("key", "INTEGER"), ("value", "TEXT")])
];

/// Key names for data stored in the misc table
enum MiscKeys {
    UserName = 0,
    AnalystName,
}

pub struct Storage {
    db: Connection,
}

impl Storage {
    pub fn load() -> Self {
        let mut path = cache_dir().expect("Could not get cache dir");
        path.push("duplex.db");
        if File::open(&path).is_ok() {
            if let Ok(db) = Connection::open(&path) {
                let mut valid_schema = true;

                // Check that tables are valid
                for (name, schema) in CHECK_DB {
                    db.pragma(Some(rusqlite::DatabaseName::Main), "table_info", name, |r| {
                        if !valid_schema {
                            return Ok(());
                        }
                        let col_name = r.get::<_, String>("name")?;
                        let col_type = r.get::<_, String>("type")?;
                        if !schema.iter().any(|e| e.0 == col_name && e.1 == col_type) {
                            error!("Invalid schema in {}: {} {}", name, col_name, col_type);
                            valid_schema = false;
                        }
                        Ok(())
                    }).expect("Invalid db scema");
                }

                if valid_schema {
                    return Self { db };
                }
                std::fs::remove_file(&path).expect("Couldn't delete bad db");
            }
        }

        let db = Connection::open(&path).expect("Couldn't create database");
        for table in CREATE_DB {
            db.execute(table, ())
                .expect("Couldn't initialize db tables");
        }
        Storage { db }
    }

    /// Checks if a users has been marked investigated and that it hasn't expired
    pub fn investigated(&self, user: &str) -> bool {
        let mut statement = match self
            .db
            .prepare("SELECT time FROM investigated_users WHERE name = :name")
        {
            Ok(s) => s,
            Err(e) => {
                error!("Could not prepare SELECT for investigated_users: {e}");
                return false;
            }
        };
        let time: i64 = match statement.query_row(&[(":name", user)], |r| r.get(0)) {
            Ok(t) => t,
            Err(e) => {
                if e != rusqlite::Error::QueryReturnedNoRows {
                    error!("Could not query SELECT for investigated_users: {e}");
                }
                return false;
            }
        };

        let investigation_expiration = 86400; // 24hrs

        let time = Local::now()
            - chrono::offset::Local
                .timestamp_opt(time, 0)
                .single()
                .unwrap_or_else(Local::now);

        time < Duration::seconds(investigation_expiration)
    }

    /// Adds or removed a user from the investigated_users table, depending on `mark`
    pub fn mark_investigated(&self, user: String, mark: bool) {
        if mark {
            let mut statement = match self
                .db
                .prepare("INSERT INTO investigated_users VALUES (?1, ?2)")
            {
                Ok(s) => s,
                Err(e) => {
                    error!("Could not prepare INSERT for investigated users: {}", e);
                    return;
                }
            };

            debug!("Running {:?}", statement);

            let now = Local::now().timestamp();
            if let Err(e) = statement.execute((user, now)) {
                error!("Could not execute INSERT for investigated_users: {}", e);
            }
        } else {
            let mut statement = match self
                .db
                .prepare("DELETE FROM investigated_users WHERE name = ?1")
            {
                Ok(s) => s,
                Err(e) => {
                    error!("Could not prepare DELETE for investigated users: {}", e);
                    return;
                }
            };

            debug!("Running {:?}", statement);

            if let Err(e) = statement.execute([user]) {
                error!("Could not execute DELETE for investigated_users: {}", e);
            }
        }
    }

    pub fn add_hdtools(&self, user: &str, info: HDToolsInfo) {
        let loc = info.1.unwrap_or_else(|| crate::user::Location {
            city: "".to_owned(),
            state: None,
            country: None,
        });
        let mut statement = match self
            .db
            .prepare("INSERT INTO hdtools VALUES (?1, ?2, ?3, ?4, ?5)")
        {
            Ok(s) => s,
            Err(e) => {
                error!("Could note prepare INSERT for hdtools: {}", e);
                return;
            }
        };

        debug!("Running {:?}", statement);

        let params = (
            user,
            info.0.timestamp(),
            loc.city,
            loc.state.unwrap_or_default(),
            loc.country.unwrap_or_default(),
        );

        if let Err(e) = statement.execute(params) {
            error!("Could not execute INSERT for hdtools: {}", e);
        }
    }

    pub fn get_hdtools(&self, user: &str) -> Option<HDToolsInfo> {
        let mut statement = match self
            .db
            .prepare("SELECT time,city,state,country FROM hdtools WHERE name = ?1")
        {
            Ok(s) => s,
            Err(e) => {
                error!("Could not prepare SELECT for hdtools: {e}");
                return None;
            }
        };

        let mut rows = match statement.query([user]) {
            Ok(r) => r,
            Err(e) => {
                error!("Could not query SELECT for hdtools: {}", e);
                return None;
            }
        };

        if let Some(row) = rows.next().ok()? {
            let date = row.get(0).ok()?;
            let date = Local.timestamp_opt(date, 0).single()?.naive_local();

            let check_empty = |x: String| if x.is_empty() { None } else { Some(x) };

            let location = Location {
                city: row.get(1).unwrap_or_default(),
                state: row.get(2).ok().and_then(check_empty),
                country: row.get(3).ok().and_then(check_empty),
            };

            return Some((date, Some(location)));
        }

        None
    }

    pub fn get_threat(&self, ip: Ipv4Addr) -> Option<IpThreat> {
        let mut statement = match self.db.prepare("SELECT * FROM ipthreat WHERE ip = ?1") {
            Ok(s) => s,
            Err(e) => {
                error!("Could not prepare SELECT for ipthreat: {e}");
                return None;
            }
        };

        let bind_ip: u32 = ip.into();
        let bind_ip = format!("{}", bind_ip);
        let mut rows = match statement.query([bind_ip.as_str()]) {
            Ok(r) => r,
            Err(e) => {
                if e != rusqlite::Error::QueryReturnedNoRows {
                    error!("Could not query SELECT for ipthreat: {e}");
                }
                return None;
            }
        };

        if let Some(row) = rows.next().ok()? {
            let is_tor = row.get::<_, i64>(1).ok()? == 1;
            let is_icloud_relay = row.get::<_, i64>(2).ok()? == 1;
            let is_proxy = row.get::<_, i64>(3).ok()? == 1;
            let is_datacenter = row.get::<_, i64>(4).ok()? == 1;
            let is_anonymous = row.get::<_, i64>(5).ok()? == 1;
            let is_known_attacker = row.get::<_, i64>(6).ok()? == 1;
            let is_known_abuser = row.get::<_, i64>(7).ok()? == 1;
            let is_threat = row.get::<_, i64>(8).ok()? == 1;
            let is_bogon = row.get::<_, i64>(9).ok()? == 1;
            let blocklists = vec![];

            let ipthreat = IpThreat {
                is_tor,
                is_icloud_relay,
                is_proxy,
                is_datacenter,
                is_anonymous,
                is_known_attacker,
                is_known_abuser,
                is_threat,
                is_bogon,
                blocklists,
            };

            return Some(ipthreat);
        }

        None
    }

    pub fn add_threat(&self, ip: Ipv4Addr, info: IpThreat) {
        let IpThreat {
            is_tor,
            is_icloud_relay,
            is_proxy,
            is_datacenter,
            is_anonymous,
            is_known_attacker,
            is_known_abuser,
            is_threat,
            is_bogon,
            blocklists: _,
        } = info;
        let args = [
            ip.into(),
            is_tor as u32,
            is_icloud_relay as u32,
            is_proxy as u32,
            is_datacenter as u32,
            is_anonymous as u32,
            is_known_attacker as u32,
            is_known_abuser as u32,
            is_threat as u32,
            is_bogon as u32,
        ];

        let mut statement = match self.db.prepare(
            "INSERT INTO ipthreat VALUES
            (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to prepare INSERT for ipthreat: {}", e);
                return;
            }
        };

        debug!("Running {:?}", statement);

        if let Err(e) = statement.execute(args) {
            error!("Could not execute INSERT for ipthreat: {}", e);
        }
    }

    pub fn get_ipinfo(&self, ip: Ipv4Addr) -> Option<IpInfo> {
        let mut statement = match self.db.prepare("SELECT * FROM ipinfo WHERE ip = :ip") {
            Ok(s) => s,
            Err(e) => {
                error!("Could not prepare SELECT on ipinfo: {e}");
                return None;
            }
        };

        let bind_ip: u32 = ip.into();
        let bind_ip = format!("{}", bind_ip);
        match statement.query_row([bind_ip.as_str()], |row| {
            let ipinfo = IpInfo {
                ip: ip.to_string(),
                hostname: row.get(1).ok(),
                city: row.get(2).unwrap_or_default(),
                region: row.get(3).unwrap_or_default(),
                country: row.get(4).unwrap_or_default(),
                loc: ip::Location {
                    lat: row.get(5).unwrap_or_default(),
                    lon: row.get(6).unwrap_or_default(),
                },
                org: row.get(7).unwrap_or_default(),
                postal: row.get(8).unwrap_or_default(),
                timezone: row.get(9).unwrap_or_default(),
            };

            Ok(ipinfo)
        }) {
            Ok(ipinfo) => Some(ipinfo),
            Err(e) => {
                if e != rusqlite::Error::QueryReturnedNoRows {
                    error!("Could not query SELECT on ipinfo: {}", e);
                }
                None
            }
        }
    }

    pub fn add_ipinfo(&self, ip: Ipv4Addr, info: IpInfo) {
        let ip: u32 = ip.into();
        let IpInfo {
            ip: _,
            hostname,
            city,
            region,
            country,
            loc,
            org,
            postal,
            timezone,
        } = info;
        let hostname = hostname.unwrap_or_default();
        let ip::Location { lat, lon } = loc;

        let params = (
            ip, hostname, city, region, country, lat, lon, org, postal, timezone,
        );

        let mut statement = match self.db.prepare(
            "INSERT INTO ipinfo VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Could not prepare INSERT for ipinfo: {}", e);
                return;
            }
        };

        debug!("Running {:?}", statement);

        if let Err(e) = statement.execute(params) {
            error!("Could not execute {:?} for ipinfo: {}", statement, e);
        }
    }

    fn get_misc(&self, key: MiscKeys) -> String {
        let mut statement = match self.db.prepare("SELECT value FROM misc WHERE key = ?1") {
            Ok(s) => s,
            Err(e) => {
                error!("Could not prepare SELECT for misc {e}");
                return String::default();
            }
        };

        match statement.query_row([key as i64], |row| row.get(0)) {
            Ok(n) => n,
            Err(e) => {
                error!("Could not bind SELECT for misc: {}", e);
                String::default()
            }
        }
    }

    pub fn get_username(&self) -> String {
        self.get_misc(MiscKeys::UserName)
    }

    pub fn get_analyst_name(&self) -> String {
        self.get_misc(MiscKeys::AnalystName)
    }

    fn set_misc(&self, key: MiscKeys, value: String) {
        let key = key as i64;
        let mut statement = match self.db.prepare("UPDATE misc SET value = ?2 WHERE key = ?1") {
            Ok(s) => s,
            Err(e) => {
                error!("Could not prepare UPDATE for misc: {}", e);
                return;
            }
        };

        debug!("Running {:?}", statement);

        if let Err(e) = statement.execute((key, value.to_owned())) {
            log::warn!("Could not execute INSERT for misc: {}", e);
            let mut statement = match self.db.prepare("INSERT INTO misc VALUES (?1, ?2)") {
                Ok(s) => s,
                Err(e) => {
                    error!("Could not prepare INSERT for misc: {}", e);
                    return;
                }
            };
            if let Err(e) = statement.execute((key, value)) {
                error!("Could not execute UPDATE for misc: {}", e);
            }
        }
    }

    pub fn set_username(&self, value: String) {
        self.set_misc(MiscKeys::UserName, value)
    }

    pub fn set_analyst_name(&self, value: String) {
        self.set_misc(MiscKeys::AnalystName, value)
    }
}
