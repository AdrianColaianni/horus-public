//! IP related queires
use log::info;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Holds static IP databases used by Splunk to geolocate IPs from Duo logs.
///
/// These databases are from <https://lite.ip2location.com>.  Splunks ipdb source is
/// <https://maxmind.com>, but MaxMind has a more limited free option so I went with IP2Location.
pub struct IpDB {
    /// IP2Location database
    iploc_db: Vec<IpLoc>,
    /// IP2Proxy database
    proxy_db: Vec<Proxy>,
    /// ASN (ISP) database
    asn_db: Vec<Asn>,
}

impl IpDB {
    /// These databases are not included in the repo as they are 323 Mb combined and GitHub refuses
    /// to host them.  They can be downloaded online by registering an account, and need some
    /// pre-processing before HORUS will accept them.  The formats are specified in their
    /// respective structs.  For the lazy people who hate up to date IP databases, you can find a
    /// copy of the pre-processed DBs in [Dev Notes](https://example.org)
    pub fn new() -> Self {
        let empty_check = |s: String| if s == "-" { None } else { Some(s) };

        let iploc_db: Vec<IpLoc> = std::include_str!("ip2location.csv")
            .par_lines()
            .map(|l| {
                let l: Vec<&str> = l.split(',').collect();
                IpLoc {
                    lower: l[0].parse().unwrap(),
                    upper: l[1].parse().unwrap(),
                    country_code: empty_check(l[2].to_string()),
                    country: empty_check(l[3].to_string()),
                    state: empty_check(l[4].to_string()),
                    city: empty_check(l[5].to_string()),
                    lat: l[l.len() - 2].parse().unwrap(),
                    lon: l[l.len() - 1].parse().unwrap(),
                }
            })
            .collect();

        let proxy_db: Vec<Proxy> = std::include_str!("ip2proxy.csv")
            .par_lines()
            .map(|l| {
                let l: Vec<&str> = l.split(',').collect();
                Proxy {
                    lower: l[0].parse().unwrap(),
                    upper: l[1].parse().unwrap(),
                }
            })
            .collect();

        let asn_db: Vec<Asn> = std::include_str!("ip2asn.csv")
            .par_lines()
            .map(|l| {
                let l: Vec<&str> = l.split(',').collect();
                Asn {
                    lower: l[0].parse().unwrap(),
                    upper: l[1].parse().unwrap(),
                    asn: empty_check(l[2].to_string()),
                }
            })
            .collect();

        info!("Loaded IP databases");

        Self {
            iploc_db,
            proxy_db,
            asn_db,
        }
    }

    pub fn get_iploc(&self, ip: Ipv4Addr) -> Option<&IpLoc> {
        let ip: u32 = ip.into();

        let i = self
            .iploc_db
            .binary_search_by(|l| {
                if l.lower > ip {
                    std::cmp::Ordering::Greater
                } else if l.upper < ip {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()?;

        Some(&self.iploc_db[i])
    }

    pub fn is_proxy(&self, ip: Ipv4Addr) -> bool {
        let ip: u32 = ip.into();

        self.proxy_db
            .binary_search_by(|l| {
                if l.lower > ip {
                    std::cmp::Ordering::Greater
                } else if l.upper < ip {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    pub fn get_asn(&self, ip: Ipv4Addr) -> Option<&String> {
        let ip: u32 = ip.into();

        let i = self
            .asn_db
            .binary_search_by(|l| {
                if l.lower > ip {
                    std::cmp::Ordering::Greater
                } else if l.upper < ip {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()?;

        self.asn_db[i].asn.as_ref()
    }
}

/// Holds the location for a range of IPs
///
/// Here is the first ten lines of the CSV file:
/// ```
/// 0,16777215,-,-,-,-,0.000000,0.000000
/// 16777216,16777471,US,United States of America,California,San Jose,37.339390,-121.894960
/// 16777472,16778239,CN,China,Fujian,Fuzhou,26.061390,119.306110
/// 16778240,16778495,AU,Australia,Tasmania,Glebe,-42.874638,147.328061
/// 16778496,16779263,AU,Australia,Victoria,Melbourne,-37.814007,144.963171
/// 16779264,16781311,CN,China,Guangdong,Guangzhou,23.127361,113.264570
/// 16781312,16785407,JP,Japan,Tokyo,Tokyo,35.689497,139.692317
/// 16785408,16793599,CN,China,Guangdong,Guangzhou,23.127361,113.264570
/// 16793600,16794623,JP,Japan,Hiroshima,Hiroshima,34.385868,132.455433
/// 16794624,16794879,JP,Japan,Miyagi,Sendai,38.266990,140.867133
/// ```
/// Each row defines a location for a range of IPs.  Notice how `-` stands in for a missing value.
#[derive(Debug, PartialEq)]
pub struct IpLoc {
    /// Lower bound of each location range in the form of a IP stored as a unsigned 32 bit integer
    pub lower: u32,
    /// Upper bound in the same format as lower
    pub upper: u32,
    /// Country code of the location
    pub country_code: Option<String>,
    /// Country name of the location
    pub country: Option<String>,
    /// State name of the location
    pub state: Option<String>,
    /// City name of the location
    pub city: Option<String>,
    /// Latitude of the location
    pub lat: f32,
    /// Longitude of the location
    pub lon: f32,
}

/// Defines a range of IPs that are proxies
///
/// Here is the first ten lines of the CSV file:
/// ```
/// 16778241,16778241
/// 16778497,16778497
/// 16780275,16780276
/// 16780285,16780285
/// 16783399,16783399
/// 16783523,16783523
/// 16783571,16783571
/// 16784584,16784584
/// 16804078,16804078
/// 16809988,16809988
/// ```
/// Each line defines a range of IPs that are proxies.  No information about what kind of proxy it
/// is retained as it is extraneous.
struct Proxy {
    lower: u32,
    upper: u32,
}

struct Asn {
    lower: u32,
    upper: u32,
    asn: Option<String>,
}

/// Network queries for IP information
///
/// This information is sourced from two services, <https://ipdata.co> and <https://ipinfo.io>.  I
/// didn't want to pay for a service and so I'm using two free services that give me ip threat info
/// and ip location info respectively.  The IP threat info is used in the context menu when you
/// right click an IP in Duplex, Simplex, or Visor.  The IP location information is used to
/// help determine the location of duo logs, as the Maxmind databases are not very accurate.
pub struct Ip {
    ipdata_key: &'static str,
    ipinfo_key: String,
}

impl Ip {
    pub fn new() -> Self {
        Self {
            // API key for ipdata.co, you will have to get your own to compile
            ipdata_key: env!("IPDATA_KEY"),
            // API key for ipinfo.io, you will have to get your own to compile
            ipinfo_key: super::basic_auth(env!("IPINFO_KEY"), None::<&str>),
        }
    }

    /// Queries ipdata.co for threat information about an IP
    pub fn get_threat(&self, ip: Ipv4Addr) -> Option<IpThreat> {
        info!("Getting IP threat for {}", ip);
        let resp = ureq::get(&format!("https://api.ipdata.co/{}/threat", ip))
            .query_pairs([("api-key", self.ipdata_key)])
            .call()
            .ok()?;

        let resp: IpThreat = resp.into_json().ok()?;

        info!("Got threat data");

        Some(resp)
    }

    /// Queries ipinfo.io for location information about an IP
    pub fn get_info(&self, ip: Ipv4Addr) -> Option<IpInfo> {
        info!("Getting IP info for {}", ip);
        let resp = ureq::get(&format!("https://ipinfo.io/{}", ip))
            .set("Authorization", &self.ipinfo_key)
            .call()
            .ok()?
            .into_json()
            .ok()?;

        info!("Got info");
        Some(resp)
    }
}

/// Information returned by ipdata.co
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct IpThreat {
    pub is_tor: bool,
    pub is_icloud_relay: bool,
    pub is_proxy: bool,
    pub is_datacenter: bool,
    pub is_anonymous: bool,
    pub is_known_attacker: bool,
    pub is_known_abuser: bool,
    pub is_threat: bool,
    pub is_bogon: bool,
    pub blocklists: Vec<Blocklist>,
}

impl IpThreat {
    pub fn vibe_check(&self) -> bool {
        !(self.is_tor
            || self.is_icloud_relay
            || self.is_proxy
            || self.is_datacenter
            || self.is_anonymous
            || self.is_known_attacker
            || self.is_known_abuser
            || self.is_threat
            || self.is_bogon
            || !self.blocklists.is_empty())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Blocklist {
    pub name: String,
    pub site: String,
    pub r#type: String,
}

/// Information returned by ipinfo.io
#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct IpInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub city: String,
    pub region: String,
    pub country: String,
    pub loc: Location,
    pub org: String,
    pub postal: String,
    pub timezone: String,
}

/// Custom serialization for ipinfo's location field
///
/// ipinfo returns the location as a string, which I am not happy with so I wrote my own
/// serialization functions to read it as a struct.
#[derive(PartialEq, Debug, Clone)]
pub struct Location {
    pub lat: f32,
    pub lon: f32,
}

impl<'de> Deserialize<'de> for Location {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let mut value = value.split(',');
        let lat: f32 = value
            .next()
            .ok_or(serde::de::Error::missing_field("lat"))?
            .parse()
            .map_err(|e: std::num::ParseFloatError| {
                serde::de::Error::unknown_variant(&e.to_string(), &["lat"])
            })?;

        let lon: f32 = value
            .next()
            .ok_or(serde::de::Error::missing_field("lon"))?
            .parse()
            .map_err(|e: std::num::ParseFloatError| {
                serde::de::Error::unknown_variant(&e.to_string(), &["lon"])
            })?;

        Ok(Location { lat, lon })
    }
}

impl Serialize for Location {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{},{}", self.lat, self.lon))
    }
}
