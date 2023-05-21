use std::{
    io::Write,
    path::PathBuf,
};

use crate::errors::HelixError;

pub enum EncryptionStates {
    PlainFileCheck,
    EncryptedBlockCheck,
}

pub enum EncryptionEndState {
    Done,
    Unchanged,
}

pub trait EncryptionObserver {
    fn update_state(&self, state: EncryptionStates);
    fn bytes_processed(&mut self, bytes: u64);
    fn failed(&self, error: HelixError);
    fn end(&self, end_state: EncryptionEndState);
}

pub trait EncryptionObserverFactory {
    fn create(&self, path: PathBuf, file_size: u64) -> Box<dyn EncryptionObserver>;
}

pub struct CliEncryptionObserverFactory;

impl EncryptionObserverFactory for CliEncryptionObserverFactory {
    fn create(&self, path: PathBuf, file_size: u64) -> Box<dyn EncryptionObserver> {
        let printer = CliEncryptionObserver::from(path, file_size);
        Box::new(printer)
    }
}

pub struct CliEncryptionObserver {
    file_size: u64,
    bytes_processed: u64,
    filename: String,
}

fn clear_line() {
    let line: String = std::iter::repeat(" ").take(80).collect();
    print!("{}\r", line);
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

impl CliEncryptionObserver {
    pub fn from(path: PathBuf, file_size: u64) -> Self {
        Self {
            file_size,
            bytes_processed: 0,
            filename: get_fixed_filename(path),
        }
    }

    fn print_file_message(&self, message: &str) {
        print!("\r");
        clear_line();
        print!("{} : {}", self.filename, message);
        std::io::stdout().flush().unwrap();
    }
}

impl EncryptionObserver for CliEncryptionObserver {
    fn update_state(&self, validations: EncryptionStates) {
        let message = match validations {
            EncryptionStates::PlainFileCheck => "Checking file change",
            EncryptionStates::EncryptedBlockCheck => "Checking encrypted block change",
        };
        self.print_file_message(message)
    }

    fn bytes_processed(&mut self, bytes: u64) {
        self.bytes_processed += bytes;
        if self.bytes_processed > self.file_size {
            self.bytes_processed = self.file_size;
        }
        let precent: f64 = (self.bytes_processed as f64 / self.file_size as f64) * 100f64;
        let message = format!("Encrypted {:.2}%", precent);
        self.print_file_message(&message);
    }

    fn failed(&self, error: HelixError) {
        let message = format!("Encryption failed, Reason : {}", error.message);
        self.print_file_message(&message);
    }

    fn end(&self, end_state: EncryptionEndState) {
        let message = match end_state {
            EncryptionEndState::Done => "Done",
            EncryptionEndState::Unchanged => "Unchanged",
        };
        self.print_file_message(message);
        print!("\n");
    }
}

pub enum DecryptionStates {
    EncryptedBlockCheck,
}

pub enum DecryptionEndState {
    Done,
    MalformedBlock,
    BlockNotFound,
}

pub trait DecryptionObserver {
    fn init_size(&mut self, file_size: u64);
    fn update_state(&self, state: DecryptionStates);
    fn bytes_processed(&mut self, bytes: u64);
    fn failed(&self, error: HelixError);
    fn end(&self, end_state: DecryptionEndState);
}

struct CliDecryptionObserver {
    prefix: String,
    file_size: Option<u64>,
    bytes_processed: u64,
}

impl CliDecryptionObserver {
    fn from(path: PathBuf) -> Self {
        CliDecryptionObserver {
            prefix: get_fixed_filename(path),
            file_size: None,
            bytes_processed: 0,
        }
    }

    fn print_file_message(&self, message: &str) {
        print!("\r");
        clear_line();
        print!("{} : {}", self.prefix, message);
        std::io::stdout().flush().unwrap();
    }
}

impl DecryptionObserver for CliDecryptionObserver {
    fn update_state(&self, state: DecryptionStates) {
        let message = match state {
            DecryptionStates::EncryptedBlockCheck => "Checking encrypted block change",
        };
        self.print_file_message(message)
    }

    fn bytes_processed(&mut self, bytes: u64) {
        let file_size = self.file_size.unwrap();
        self.bytes_processed += bytes;
        if self.bytes_processed > file_size {
            self.bytes_processed = file_size;
        }
        let precent: f64 = (self.bytes_processed as f64 / file_size as f64) * 100f64;
        let message = format!("Decrypted {:.2}%", precent);
        self.print_file_message(&message);
    }

    fn failed(&self, error: HelixError) {
        let message = format!("Encryption failed, Reason : {}", error.message);
        self.print_file_message(&message);
    }

    fn end(&self, end_state: DecryptionEndState) {
        let message = match end_state {
            DecryptionEndState::Done => "Done",
            DecryptionEndState::MalformedBlock => "Block Malformed",
            DecryptionEndState::BlockNotFound => "Block not found",
        };
        self.print_file_message(message);
        print!("\n");
    }

    fn init_size(&mut self, file_size: u64) {
        self.file_size = Some(file_size);
    }
}

pub trait DecryptionObserverFactory {
    fn create(&self, path: PathBuf) -> Box<dyn DecryptionObserver>;
}

pub struct CliDecryptionObserverFactory;

impl DecryptionObserverFactory for CliDecryptionObserverFactory {
    fn create(&self, path: PathBuf) -> Box<dyn DecryptionObserver> {
        let observer = CliDecryptionObserver::from(path);
        Box::new(observer)
    }
}
