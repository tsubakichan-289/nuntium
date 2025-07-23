#![allow(dead_code)]
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct PathManager {
    main: PathBuf,   // /usr/local/nuntium/
    config: PathBuf, // /opt/nuntium/
    log: PathBuf,    // /var/log/nuntium/
    tmp: PathBuf,    // /var/tmp/nuntium/
}

impl PathManager {
    pub fn new() -> io::Result<Self> {
        let main = PathBuf::from("/usr/local/nuntium/");
        let config = PathBuf::from("/opt/nuntium/");
        let log = PathBuf::from("/var/log/nuntium/");
        let tmp = PathBuf::from("/var/tmp/nuntium/");

        let paths = [&main, &config, &log, &tmp];
        for path in paths {
            if !path.exists() {
                fs::create_dir_all(path)?;
            }
        }

        Ok(Self {
            main,
            config,
            log,
            tmp,
        })
    }

    pub fn main_dir(&self) -> &Path {
        &self.main
    }

    pub fn config_dir(&self) -> &Path {
        &self.config
    }

    pub fn log_dir(&self) -> &Path {
        &self.log
    }

    pub fn tmp_dir(&self) -> &Path {
        &self.tmp
    }

    pub fn kyber_public_key_path(&self) -> PathBuf {
        self.config.join("kyber1024_public.hex")
    }

    pub fn kyber_secret_key_path(&self) -> PathBuf {
        self.config.join("kyber1024_secret.hex")
    }

    pub fn nuntium_config_path(&self) -> PathBuf {
        self.config.join("nuntium.conf")
    }

    pub fn client_db_path(&self) -> PathBuf {
        self.config.join("clients.json")
    }
}
