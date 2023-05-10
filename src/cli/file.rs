use std::{io::Write, path::{Path, PathBuf}};

use crate::{errors::HelixError, observer::Observer};

use super::Operation;

pub struct FileObserver;

impl Observer<Operation<PathBuf>, (PathBuf, HelixError)> for FileObserver {
    fn on_event(&self, data: &Operation<PathBuf>) {
        match data {
            Operation::Begin(path) => {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                print!("\rEncrypting {}", file_name);
                std::io::stdout().flush().unwrap();
            }
            Operation::End(path) => {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                println!("\rEncrypted {}", file_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }

    fn on_error(&self, data: &(PathBuf, HelixError)) {
        let file_name = data.0.file_name().unwrap().to_str().unwrap();
        let reason = &data.1.message;
        println!("Filed to Encrypt {}, Reason : {}", file_name, reason);
    }
}
