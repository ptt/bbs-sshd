use serde_derive::Deserialize;

#[derive(Deserialize)]
pub(crate) struct Config {
    pub bind: Vec<String>,
    pub host_keys: Vec<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub workers: Option<usize>,
}
