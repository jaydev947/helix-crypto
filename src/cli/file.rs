use std::{
    io::Write,
    path::{Path, PathBuf},
};

use crate::{errors::HelixError, observer::Observer};

use super::Operation;

pub struct FileObserver;

pub enum ValidationStates {
    PlainFileCheck,
    EncryptedBlockCheck,
    Unchanged,
}

pub trait EncryptionObserver {
    fn update_state(&self, validations: ValidationStates);
    fn update_chunk_encrypted(&self, chunk_number: u32);
    fn failed(&self, error: HelixError);
    fn end(&self);
}

pub trait EncryptionObserverFactory {
    fn create(&self, path: PathBuf, file_size: u64, chunk_size: u32)
        -> Box<dyn EncryptionObserver>;
}

pub struct CliEncryptionObserverFactory;

impl EncryptionObserverFactory for CliEncryptionObserverFactory {
    fn create(
        &self,
        path: PathBuf,
        file_size: u64,
        chunk_size: u32,
    ) -> Box<dyn EncryptionObserver> {
        let printer = CliPrinter::from(path, file_size, chunk_size);
        Box::new(printer)
    }
}

pub struct CliPrinter {
    file_size: u64,
    chunk_size: u32,
    filename: String,
}

fn clear_line() {
    // print!("{}[2J", 27 as char);
    print!("                                                                \r");
}

impl CliPrinter {
    pub fn from(path: PathBuf, file_size: u64, chunk_size: u32) -> Self {
        Self {
            file_size,
            chunk_size,
            filename: Self::get_fixed_filename(path),
        }
    }

    fn print_file_message(&self, message: &str) {
        print!("\r");
        clear_line();
        print!("{} : {}", self.filename, message);
        std::io::stdout().flush().unwrap();
    }

    fn get_fixed_filename(path: PathBuf) -> String {
        let size = 20;
        let filename = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap();
        if filename.len() < size {
            let spaces = " ".repeat(size - filename.len());
            return format!("{}{}", filename, spaces);
        } else if filename.len() > size {
            let trimmed = &filename[..size - 3];
            return format!("{}...", trimmed);
        }
        filename
    }
}

impl EncryptionObserver for CliPrinter {
    fn update_state(&self, validations: ValidationStates) {
        let message = match validations {
            ValidationStates::PlainFileCheck => "Checking file change",
            ValidationStates::EncryptedBlockCheck => "Checking encrypted block change",
            ValidationStates::Unchanged => "File and block unchanged",
        };
        self.print_file_message(message)
    }

    fn update_chunk_encrypted(&self, chunk_number: u32) {
        let mut current_size = (self.chunk_size * chunk_number) as u64;
        if current_size > self.file_size {
            current_size = self.file_size;
        }
        let precent: f64 = (current_size as f64 / self.file_size as f64) * 100f64;
        let message = format!("Encrypted {:.2}%", precent);
        self.print_file_message(&message);
    }

    fn failed(&self, error: HelixError) {
        let message = format!("Encryption failed, Reason : {}", error.message);
        self.print_file_message(&message);
    }

    fn end(&self) {
        print!("\n");
    }
}

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
