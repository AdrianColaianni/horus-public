//! HDTools queries
//!
//! This module holds the shibsession and functions used to retrieve user data from HDTools
use std::sync::OnceLock;

use crate::user::Location;
use chrono::NaiveDateTime;
use cookie_store::{Cookie, CookieStore};
use log::{debug, info};
use regex::Regex;
use ureq::Agent;

static USER_RE: OnceLock<Regex> = OnceLock::new();
static CREATE_DATE_RE: OnceLock<Regex> = OnceLock::new();
static STUDENT_ADDRESS_RE: OnceLock<Regex> = OnceLock::new();
static EMPLOYEE_ADDRESS_RE: OnceLock<Regex> = OnceLock::new();

pub type HDToolsInfo = (NaiveDateTime, Option<Location>);

pub struct HDTools {
    agent: Agent,
}

impl HDTools {
    pub fn new(shibsession: String) -> Option<Self> {
        let url: url::Url = "https://TOP_SNEAKY_URL"
            .parse()
            .expect("Bad HDTools URL");

        let cookie = Cookie::parse(shibsession, &url).expect("Failed to set shibsession cookie");
        let mut cookie_store = CookieStore::default();
        cookie_store
            .insert(cookie, &url)
            .expect("Failed to insert cookie into cookie store");

        let agent = ureq::builder()
            .cookie_store(cookie_store)
            .redirects(0)
            .build();

        let status = match agent
            .get("https://TOP_SNEAKY_URL")
            .call()
        {
            Ok(s) => s.status(),
            Err(_) => return None,
        };

        info!("HDTools status was {}", status);

        if status == 200 {
            Some(Self { agent })
        } else {
            None
        }
    }

    pub fn get_info(&self, user: &str) -> Option<HDToolsInfo> {
        info!("Fetching HDTools info for {}", user);
        let resp = self
            .agent
            .get(&format!(
                "https://TOP_SNEAKY_URL/{}",
                user
            ))
            .call()
            .ok()?
            .into_string()
            .ok()?;

        let zid = USER_RE
            .get_or_init(|| Regex::new(r#""zid":"(\S+?)""#).unwrap())
            .captures(&resp)?[1]
            .to_owned();

        debug!("Got zid: {}", zid);

        let resp = self
            .agent
            .get(&format!(
                "https://TOP_SNEAKY_URL/{}",
                zid
            ))
            .call()
            .ok()?
            .into_string()
            .ok()?;

        debug!("Processing creation date");

        let creation_date = CREATE_DATE_RE
            .get_or_init(|| Regex::new(r#""createDate":"(\S+?)""#).unwrap())
            .captures(&resp)?;

        let creation_date: NaiveDateTime =
            chrono::DateTime::parse_from_str(&creation_date[1], "%FT%T%z")
                .ok()?
                .with_timezone(&chrono::Local)
                .naive_local();

        let resp = self
            .agent
            .get(&format!(
                "https://TOP_SNEAKY_URL/{}",
                zid
            ))
            .call()
            .ok()?
            .into_string()
            .ok()?;

        debug!("Got student records");

        let addr = STUDENT_ADDRESS_RE.get_or_init(|| Regex::new(r#""(?:primary|campus)AddressCity":"(?<city>[^"]*)"(?:,"(?:primary|campus)AddressState":"(?<state>[^"]*)")?(?:.*,"(?:primary|campus)AddressCountry":"(?<country>[^"]*)")?"#).unwrap()).captures(&resp);

        match addr {
            Some(addr) => {
                debug!("Capture: {}", &addr[0]);
                let addr = Location {
                    city: addr["city"].to_owned(),
                    state: addr.name("state").map(|s| s.as_str().to_owned()),
                    country: addr.name("country").map(|s| s.as_str().to_owned()),
                };

                Some((creation_date, Some(addr)))
            }
            None => {
                let resp = self
                    .agent
                    .get(&format!(
                        "https://TOP_SNEAKY_URL/{}",
                        zid
                    ))
                    .call()
                    .ok()?
                    .into_string()
                    .ok()?;

                debug!("Got employee records");

                let addr = EMPLOYEE_ADDRESS_RE
                    .get_or_init(|| {
                        Regex::new(r#""hCity":"(?<city>[^"]*)","hState":"(?<state>[^"]*)""#)
                            .unwrap()
                    })
                    .captures(&resp)
                    .map(|cap| Location {
                        city: cap["city"].to_owned(),
                        state: Some(cap["state"].to_owned()),
                        country: None,
                    });

                Some((creation_date, addr))
            }
        }
    }
}
