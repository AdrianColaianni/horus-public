//! One Duo Log
//!
//! I hear you thinking "oh my oh dear oh what have we here why do you serialize JSON with regex?"
//! You may even be clutching you stomach to avoid throwing up at the sight of so much regex.  Let
//! me explain.  The Splunk duo logs were not created equal, and many have fields in different
//! places, fields in fields, or fields in strings in fields.  It would be far too complex and
//! inefficient to try parsing the login to several structs, or parse to
//! [serde_json::value](https://docs.rs/serde_json/latest/serde_json/value/index.html) and build a
//! struct from there.  I instead chose to write several regex patterns for pulling out the
//! necessary values.  This has been far more reliable than my original implementation, which did
//! parse to [serde_json::value](https://docs.rs/serde_json/latest/serde_json/value/index.html). I
//! love regex, real homies use regex, regex doesn't insult my code or question my decision making.
use crate::queries::ip::IpDB;
use chrono::{Local, NaiveDateTime, TimeZone};
use log::{debug, warn};
use regex::Regex;
use std::{net::Ipv4Addr, sync::OnceLock};

const DATE_FORMAT: &str = "%F %T%.3f %Z";

const VPN_IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(130, 127, 255, 220),
    Ipv4Addr::new(130, 127, 255, 222),
    Ipv4Addr::new(0, 0, 0, 0),
];

static USERNAME_RE: OnceLock<Regex> = OnceLock::new();
static TIME_RE: OnceLock<Regex> = OnceLock::new();
static DEVICE_RE: OnceLock<Regex> = OnceLock::new();
static FACTOR_RE: OnceLock<Regex> = OnceLock::new();
static INTEGRATION_RE: OnceLock<Regex> = OnceLock::new();
static REASON_RE: OnceLock<Regex> = OnceLock::new();
static RESULT_RE: OnceLock<Regex> = OnceLock::new();
static IP_RE: OnceLock<Regex> = OnceLock::new();

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Integration {
    Shibboleth,
    Citrix,
    CuVpn,
    Linux,
    Adfs,
    Dmp,
    Rdp,
    PasswordReset,
    Splunk,
    Other(String),
    None,
}

impl std::fmt::Display for Integration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Shibboleth => "Shibboleth",
                Self::Citrix => "Citrix",
                Self::CuVpn => "CUVPN",
                Self::Linux => "Linux Access",
                Self::Adfs => "ADFS",
                Self::Dmp => "Device Management",
                Self::Rdp => "RDP",
                Self::PasswordReset => "Password Reset",
                Self::Splunk => "Splunk",
                Self::Other(s) => s,
                Self::None => "None",
            }
        )
    }
}

impl From<&str> for Integration {
    fn from(int: &str) -> Self {
        match int {
            "Shibboleth" => Self::Shibboleth,
            "Shibboleth External" => Self::Shibboleth,
            "Radius Proxy Duo Only (Citrix)" => Self::Citrix,
            "Clemson University VPN" => Self::CuVpn,
            "UNIX Application (Palmetto)" => Self::Linux,
            "adfs.clemson.edu" => Self::Adfs,
            "Device Management Portal Protected Resource" => Self::Dmp,
            "Device Management Portal" => Self::Dmp,
            "Microsoft RDP Gateway" => Self::Rdp,
            "Password Reset on IDP" => Self::PasswordReset,
            "School of Computing Linux Access" => Self::Linux,
            "CU Splunk" => Self::Splunk,
            "CECAS Linux Fastx Access" => Self::Linux,
            "Infrastucture Linux Host" => Self::Linux,
            _ => Self::Other(int.to_owned()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LoginResult {
    Success,
    Failure,
    Fraud,
    None,
    Other(String),
}

impl std::fmt::Display for LoginResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Success => "Success",
                Self::Failure => "Failure",
                Self::Fraud => "Fraud",
                Self::None => "None",
                Self::Other(s) => s,
            }
        )
    }
}

impl From<&str> for LoginResult {
    fn from(res: &str) -> Self {
        match res {
            "SUCCESS" => LoginResult::Success,
            "FAILURE" => LoginResult::Failure,
            "FRAUD" => LoginResult::Fraud,
            s => LoginResult::Other(s.to_owned()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Factor {
    DuoPush,
    None,
    Bypass,
    RememberedDevice,
    SMSPasscode,
    Passcode,
    HardwareToken,
    PhoneCall,
    SecurityKey, // Youbikey, touchID
}

impl std::fmt::Display for Factor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::DuoPush => "Duo push",
                Self::RememberedDevice => "Remembered device",
                Self::SMSPasscode => "SMS passcode",
                Self::Passcode => "Passcode",
                Self::HardwareToken => "Hardware token",
                Self::PhoneCall => "Phone call",
                Self::SecurityKey => "Security Key",
                Self::Bypass => "Bypass code",
                Self::None => "None",
            }
        )
    }
}

impl From<&str> for Factor {
    fn from(fac: &str) -> Self {
        match fac {
            "Duo Push" => Self::DuoPush,
            "n/a" => Self::None,
            "Bypass Status" => Self::Bypass,
            "Remembered Device" => Self::RememberedDevice,
            "SMS Passcode" => Self::SMSPasscode,
            "Passcode" => Self::Passcode,
            "Hardware Token" => Self::HardwareToken,
            "Phone Call" => Self::PhoneCall,
            "Touch ID (WebAuthn)" => Self::SecurityKey,
            "Yubikey Passcode" => Self::SecurityKey,
            "Security Key (WebAuthn)" => Self::SecurityKey,
            "Bypass Code" => Self::Bypass,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    UserApproved,
    Bypass,
    RememberedDevice,
    ValidPasscode,
    TrustedNetwork,
    NoResponse,
    UserCancelled,
    InvalidPasscode,
    DenyUnenrolledUser,
    LockedOut,
    UserMistake,
    Error,
    RestrictedOFAC,
    None,
    Other(String),
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::UserApproved => "User approved",
                Self::TrustedNetwork => "Trusted network",
                Self::RememberedDevice => "Remembered device",
                Self::ValidPasscode => "Valid passcode",
                Self::Bypass => "Bypass",
                Self::NoResponse => "No response",
                Self::UserCancelled => "User cancelled",
                Self::InvalidPasscode => "Invalid passcode",
                Self::LockedOut => "Locked out",
                Self::DenyUnenrolledUser => "Deny unenrolled user",
                Self::Error => "Error",
                Self::RestrictedOFAC => "Restricted Location",
                Self::UserMistake => "User mistake",
                Self::Other(s) => s,
                Self::None => "None",
            }
        )
    }
}

impl From<&str> for Reason {
    fn from(res: &str) -> Self {
        match res.to_lowercase().as_str() {
            "user approved" => Self::UserApproved,
            "trusted network" => Self::TrustedNetwork,
            "remembered device" => Self::RememberedDevice,
            "valid passcode" => Self::ValidPasscode,
            "bypass user" => Self::Bypass,
            "no response" => Self::NoResponse,
            "user cancelled" => Self::UserCancelled,
            "invalid passcode" => Self::InvalidPasscode,
            "locked out" => Self::LockedOut,
            "deny unenrolled user" => Self::DenyUnenrolledUser,
            "error" => Self::Error,
            "restricted ofac location" => Self::RestrictedOFAC,
            "user mistake" => Self::UserMistake,
            s => Self::Other(s.to_owned()),
        }
    }
}

/// Represents one duo log
#[derive(Debug, Clone)]
pub struct Login {
    pub time: NaiveDateTime,
    pub user: String,
    pub device: Option<String>,
    pub factor: Factor,
    pub integration: Integration,
    pub reason: Reason,
    pub result: LoginResult,
    pub ip: Option<Ipv4Addr>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub location: Option<(f32, f32)>,
    /// True if the IP is an known relay
    pub is_relay: bool,
    /// Service Provider for the IP
    pub asn: Option<String>,
    /// Why the login was flagged
    pub flag_reasons: Vec<FlagReason>,
}

impl PartialOrd for Login {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        other.time.partial_cmp(&self.time)
    }
}

impl Eq for Login {}

impl PartialEq for Login {
    fn eq(&self, other: &Self) -> bool {
        other.time == self.time && other.user == self.user
    }
}

impl Ord for Login {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.time.cmp(&self.time)
    }
}

impl Login {
    /// Serializes one JSON line of duo logs to a Login.  Returns [None] if there is no username,
    /// or the username is euqal to `System` or has a space in it (gets rid of `API Vault User` and
    /// such)
    pub fn new(obj: &str, ipdb: &IpDB) -> Option<Self> {
        let obj = obj.replace('\\', "");

        let user: String = match USERNAME_RE
            .get_or_init(|| Regex::new(r#""user": ?"([^"]+)""#).unwrap())
            .captures(&obj)
        {
            Some(user) => user[1].to_owned(),
            None => {
                warn!("Couldn't find user: {}", obj);
                return None;
            }
        };

        if user.contains(' ') || user == "System" {
            return None;
        }

        debug!("Parsing log for {}", user);

        let time = match TIME_RE
            .get_or_init(|| Regex::new(r#""_time": ?"([^"]*)""#).unwrap())
            .captures(&obj)
        {
            Some(cap) => match Local.datetime_from_str(&cap[1], DATE_FORMAT) {
                Ok(time) => time.with_timezone(&Local).naive_local(),
                Err(_) => {
                    warn!("Couldn't parse time of {} for user {}", &cap[1], user);
                    return None;
                }
            },
            None => {
                return None;
            }
        };

        let device = DEVICE_RE
            .get_or_init(|| Regex::new(r#""device": ?"([^"]+)""#).unwrap())
            .captures(&obj)
            .map(|c| c[1].to_owned());

        let factor = FACTOR_RE
            .get_or_init(|| Regex::new(r#""factor": ?"([^"]+)""#).unwrap())
            .captures(&obj)
            .map_or(Factor::None, |c| c[1].into());

        let integration = INTEGRATION_RE
            .get_or_init(|| Regex::new(r#""integration": ?"([^"]+)""#).unwrap())
            .captures(&obj)
            .map_or(Integration::None, |c| c[1].into());

        let reason = REASON_RE
            .get_or_init(|| Regex::new(r#""reason": ?"([^"]+)""#).unwrap())
            .captures(&obj)
            .map_or(Reason::None, |c| c[1].into());

        let result = RESULT_RE
            .get_or_init(|| Regex::new(r#""result": ?"([^"]+)""#).unwrap())
            .captures(&obj)
            .map_or(LoginResult::None, |c| c[1].into());

        let ip = IP_RE
            .get_or_init(|| Regex::new(r#""ip": ?"([^"]+)""#).unwrap())
            .captures(&obj)
            .and_then(|c| {
                c[1].parse().ok().or_else(|| {
                    let ip = c[1].to_string();
                    if ip == "localhost" {
                        Some(Ipv4Addr::LOCALHOST)
                    } else {
                        // Try to parse from hostname
                        match ip.split('.').next() {
                            Some(ip) => ip.replace('-', ".").parse().ok(),
                            None => {
                                warn!("Couldn't parse ip for user {}: {}", user, ip);
                                None
                            }
                        }
                    }
                })
            });

        let (mut country, mut state, mut city, mut location, mut asn) =
            (None, None, None, None, None);
        let mut is_relay = false;
        if let Some(ip) = ip {
            if let Some(iploc) = ipdb.get_iploc(ip) {
                country = iploc.country_code.to_owned();
                state = iploc.state.to_owned();
                city = iploc.city.to_owned();
                location = Some((iploc.lat, iploc.lon));
            }
            is_relay = ipdb.is_proxy(ip);
            asn = ipdb.get_asn(ip).cloned();
        }

        Some(Login {
            city,
            country,
            device,
            factor,
            integration,
            ip,
            location,
            reason,
            result,
            state,
            time,
            user,
            is_relay,
            asn,
            flag_reasons: vec![],
        })
    }

    pub fn is_vpn_ip(&self) -> bool {
        if let Some(ip) = &self.ip {
            if VPN_IPS.contains(ip) {
                return true;
            }
        }
        false
    }

    pub fn is_priv_ip(&self) -> bool {
        if let Some(ip) = &self.ip {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
        } else {
            false
        }
    }

    pub fn format_location(&self) -> Option<String> {
        if self.is_vpn_ip() {
            return Some("VPN".to_owned());
        }
        match &self.country {
            None => None,
            Some(country) => match &self.state {
                None => Some(country.to_string()),
                Some(state) => match &self.city {
                    None => Some(format!("{}, {}", state, country)),
                    Some(city) => Some(format!("{}, {}, {}", city, state, country)),
                },
            },
        }
    }
}

/// Represents a reason why a login or user is flagged
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagReason {
    Fraud,
    Failure,
    Dmp,
    Travel,
}

impl std::fmt::Display for FlagReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FlagReason::Fraud => "Fraud",
                FlagReason::Failure => "Failure",
                FlagReason::Dmp => "DMP",
                FlagReason::Travel => "Travel",
            }
        )
    }
}
