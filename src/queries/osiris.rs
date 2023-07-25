//! Osiris (Zeppelin backend) queries
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::NaiveDate;
use log::info;
use serde::{Deserialize, Serialize};

/// I tried to be a good little boy who uses TLS but the wiki certs don't have a local issuer
/// certificate 😩
const URL: &str = "http://csoc-wiki.clemson.edu";

pub struct Osiris {
    /// The super secret API key shared by Horus and Osiris
    auth: String,
}

impl Osiris {
    pub fn new() -> Self {
        Self {
            auth: STANDARD.encode(env!("OSIRIS_API_KEY")),
        }
    }

    pub fn get_date(&self, day: NaiveDate) -> Option<Data> {
        info!("Getting data for {} from Osiris", day.format("%F"));
        let data = ureq::get(&format!("{}/{}", URL, day.format("%F")))
            .set("Authorization", &self.auth)
            .call()
            .ok()?
            .into_json()
            .ok();

        info!("Retrieved data");
        data
    }

    pub fn post_date(&self, day: NaiveDate, data: Data) -> Option<()> {
        info!("Posting data for {} to Osiris", day.format("%F"));
        ureq::post(&format!("{}/{}", URL, day.format("%F")))
            .set("Authorization", &self.auth)
            .send_json(data)
            .ok()?;

        info!("Successfult sent data");
        Some(())
    }

    pub fn get(&self) -> Option<Vec<(String, Data)>> {
        info!("Getting data from Osiris");
        let resp = ureq::get(URL)
            .set("Authorization", &self.auth)
            .call()
            .ok()?
            .into_json()
            .ok()?;

        info!("Got data");
        resp
    }
}

#[derive(Serialize, Deserialize)]
pub struct Data {
    pub incidents: Vec<(String, i64)>,
    pub investigations: Vec<(String, i64)>,
}
