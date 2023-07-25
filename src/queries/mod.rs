//! Holds network queries
use std::sync::Arc;
pub mod hdtools;
pub mod ip;
pub mod osiris;
pub mod splunk;
mod test;

/// Stores all the query sources
///
/// This handles wrapping (`Arc<>`) and holding on to the queries
pub struct Queries {
    /// Splunk queries
    pub splunk: Arc<splunk::Splunk>,
    /// HDTools queries - entering a shibsession is optional and thus so is the struct
    pub hdtools: Option<Arc<hdtools::HDTools>>,
    /// IP information queries
    pub ipq: Arc<ip::Ip>,
    /// Osiris queries
    pub osiris: Arc<osiris::Osiris>,
}

impl Queries {
    pub fn new(splunk: splunk::Splunk, hdtools: Option<hdtools::HDTools>) -> Self {
        Queries {
            splunk: Arc::new(splunk),
            hdtools: hdtools.map(Arc::new),
            ipq: Arc::new(ip::Ip::new()),
            osiris: Arc::new(osiris::Osiris::new()),
        }
    }
}

/// Encodes username & password for basic HTTP auth in compliance with
/// [RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235)
fn basic_auth<U, P>(username: U, password: Option<P>) -> String
where
    U: std::fmt::Display,
    P: std::fmt::Display,
{
    use base64::prelude::BASE64_STANDARD;
    use base64::write::EncoderWriter;
    use std::io::Write;

    let mut buf = b"Basic ".to_vec();
    {
        let mut encoder = EncoderWriter::new(&mut buf, &BASE64_STANDARD);
        let _ = write!(encoder, "{}:", username);
        if let Some(password) = password {
            let _ = write!(encoder, "{}", password);
        }
    }

    unsafe { std::str::from_utf8_unchecked(&buf).to_owned() }
}
