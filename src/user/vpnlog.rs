//! One log from `splunk_network_cisco`
//!
//! See [super::login] for why there's so much regex
use crate::queries::ip::IpDB;
use chrono::NaiveDateTime;
use regex::Regex;
use std::{net::Ipv4Addr, sync::OnceLock};

const DATE_FORMAT: &str = "%F %T%.3f %Z";

static TIME_RE: OnceLock<Regex> = OnceLock::new();
static VPN_IP_RE: OnceLock<Regex> = OnceLock::new();
static SOURCE_IP_RE: OnceLock<Regex> = OnceLock::new();
static PLATFORM_RE: OnceLock<Regex> = OnceLock::new();
static MAC_RE: OnceLock<Regex> = OnceLock::new();
static USER_AGENT_RE: OnceLock<Regex> = OnceLock::new();

pub struct VpnLog {
    pub time: NaiveDateTime,
    pub vpn_ip: Ipv4Addr,
    pub source_ip: Ipv4Addr,
    pub dev_platform: String,
    pub dev_mac: Option<String>,
    pub user_agent: String,
    /// True if the log correlates to the previous log
    pub correlate_prev: bool,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    /// True if the IP is an identified relay
    pub is_relay: bool,
}

impl VpnLog {
    pub fn new(log: &str, ipdb: &IpDB) -> Option<Self> {
        let time = TIME_RE
            .get_or_init(|| Regex::new(r#""_time": ?"([^"]+)""#).unwrap())
            .captures(log)?[1]
            .to_string();
        let time = NaiveDateTime::parse_from_str(&time, DATE_FORMAT).ok()?;
        let vpn_ip: Ipv4Addr = VPN_IP_RE
            .get_or_init(|| Regex::new(r#"Framed-IP-Address=([^,]+)"#).unwrap())
            .captures(log)?[1]
            .parse()
            .ok()?;
        let source_ip: Ipv4Addr = SOURCE_IP_RE
            .get_or_init(|| Regex::new(r#"Calling-Station-ID=([^,]+)"#).unwrap())
            .captures(log)?[1]
            .parse()
            .ok()?;
        let dev_platform = PLATFORM_RE
            .get_or_init(|| Regex::new(r#"device-platform=([^,]+)"#).unwrap())
            .captures(log)?[1]
            .to_string();
        let dev_mac = MAC_RE
            .get_or_init(|| Regex::new(r#"device-mac=([0-9a-f\-:]{17})"#).unwrap())
            .captures(log)
            .map(|c| c[1].to_string());
        let user_agent = USER_AGENT_RE
            .get_or_init(|| Regex::new(r#"user-agent=([^,]+)"#).unwrap())
            .captures(log)?[1]
            .to_string();

        let (mut city, mut state, mut country) = (None, None, None);
        if let Some(loc) = ipdb.get_iploc(source_ip) {
            city = loc.city.to_owned();
            state = loc.state.to_owned();
            country = loc.country_code.to_owned();
        }
        let is_relay = ipdb.is_proxy(source_ip);

        Some(Self {
            time,
            vpn_ip,
            source_ip,
            dev_platform,
            dev_mac,
            user_agent,
            correlate_prev: false,
            city,
            state,
            country,
            is_relay,
        })
    }

    pub fn correlates(&self, other: &Self) -> bool {
        self.source_ip == other.source_ip
            || (self.dev_mac.is_some() && self.dev_mac == other.dev_mac)
    }

    pub fn format_location(&self) -> Option<String> {
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

impl PartialEq for VpnLog {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}

impl Eq for VpnLog {}

impl PartialOrd for VpnLog {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(other.time.cmp(&self.time))
    }
}

impl Ord for VpnLog {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.time.cmp(&self.time)
    }
}
