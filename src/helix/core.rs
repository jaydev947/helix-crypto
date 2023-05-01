use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
};

use rand::Error;
use rusqlite::Connection;

use crate::{
    crypto::{
        chacha::{
            decryptors::ByteDecryptorImpl,
            encryptors::ByteEncryptorImpl,
            keys::{Key, KeyDecryptor, KeyEncryptor},
        },
        ByteDecryptor, ByteEncryptor,
    },
    filecrypto::{
        chacha::{decryptors::CCFileDecryptor, encryptors::CCFileEncryptor},
        FileDecryptor, FileEncryptor,
    },
    storage::{schema::HelixSchemaCreator, File, FileStore, MasterKey, MasterKeyStore},
    util::{
        hash::{hash_file, hash_string},
        hex::{decode, decode_vec, encode_vec},
        uuid::generate,
    },
};

use super::{
    errors::HelixError,
    files::{HelixFileDecryptor, HelixFileEncryptor},
    folder_walker::get_files,
    master_key::MasterKeyManager,
};

struct HelixState {
    connection: Connection,
    master_key: Key,
    block_directory: PathBuf,
}

struct HelixEncryptor<'a> {
    source: &'a str,
    destination: &'a str,
    passphrase: &'a str,
    helix_state: Option<HelixState>,
}

impl<'a> HelixEncryptor<'a> {
    pub fn from(source: &'a str, destination: &'a str, passphrase: &'a str) -> Self {
        Self {
            source,
            destination,
            passphrase,
            helix_state: None,
        }
    }

    fn check_helix_setup(&mut self) {
        if self.helix_state.is_some() {
            return;
        }
        let destination_path = Path::new(self.destination);
        let helix_folder = destination_path.join(".helix");
        let db_file_path = helix_folder.join("metadata.db");
        let block_path = helix_folder.join("blocks");
        create_dir_all(&block_path).unwrap();
        let connection = Connection::open(db_file_path).unwrap();
        HelixSchemaCreator::create(&connection);
        let master_key = self.get_master_key(&connection);
        self.helix_state = Some(HelixState {
            connection,
            master_key: master_key,
            block_directory: block_path,
        })
    }

    fn get_master_key(&self, connection: &Connection) -> Key {
        let master_key_manager = MasterKeyManager::from(connection);
        let master_key = match master_key_manager.get(self.passphrase).unwrap() {
            Some(key) => key,
            None => master_key_manager.generate(self.passphrase),
        };
        master_key
    }

    pub fn encrypt(&mut self) -> Result<(), HelixError> {
        self.check_helix_setup();
        let paths = get_files(self.source);
        if paths.len() == 0 {
            return Ok(());
        }
        let state = self.helix_state.as_ref().unwrap();
        let helix_encryptor = HelixFileEncryptor::from(
            state.block_directory.to_str().unwrap(),
            &state.master_key,
            &state.connection,
        );
        for path in paths {
            let path_str = path.to_str().unwrap();
            print!("encrypting {}", path_str);
            helix_encryptor.encrypt(path_str);
            print!("encrypted {}", path_str);
        }
        Ok(())
    }
}

pub struct HelixDecryptor<'a> {
    source: &'a str,
    destination: &'a str,
    passphrase: &'a str,
    helix_state: Option<HelixState>,
}

impl<'a> HelixDecryptor<'a> {
    pub fn from(source: &'a str, destination: &'a str, passphrase: &'a str) -> Self {
        Self {
            source,
            destination,
            passphrase,
            helix_state: None,
        }
    }

    fn check_helix_setup(&mut self) -> Result<(), HelixError> {
        if self.helix_state.is_some() {
            return Ok(());
        }
        let source_path = Path::new(self.source);
        let helix_folder = source_path.join(".helix");
        if !helix_folder.exists() {
            return Err(HelixError::from(
                "InvalidHelixSpace",
                "NoHelixFolder",
                ".helix folder not found",
            ));
        }
        let db_file_path = helix_folder.join("metadata.db");
        if !db_file_path.exists() {
            return Err(HelixError::from(
                "InvalidHelixSpace",
                "NoDBFile",
                "metadata.db file not found",
            ));
        }
        let block_path = helix_folder.join("blocks");
        if !block_path.exists() {
            return Err(HelixError::from(
                "InvalidHelixSpace",
                "NoBlocksFolder",
                "blocks folder not found",
            ));
        }
        let connection = Connection::open(db_file_path).unwrap();
        let master_key = self.get_master_key(&connection)?;
        self.helix_state = Some(HelixState {
            connection,
            master_key: master_key,
            block_directory: block_path,
        });
        Ok(())
    }

    fn get_master_key(&self, connection: &Connection) -> Result<Key, HelixError> {
        let master_key_manager = MasterKeyManager::from(connection);
        match master_key_manager.get(self.passphrase)? {
            Some(key) => Ok(key),
            None => Err(HelixError::from(
                "InvalidHelixSpace",
                "NoMasterKey",
                "Master Key not found in db",
            )),
        }
    }

    pub(super) fn decrypt(&self) -> Result<(), HelixError> {
        let state = self.helix_state.as_ref().unwrap();
        let file_store = FileStore::from(&state.connection);
        let files = file_store.get_all();
        if files.len() == 0 {
            return Ok(());
        }
        let helix_file_decryptor = HelixFileDecryptor::from(
            state.block_directory.to_str().unwrap(),
            &state.master_key,
            &state.connection,
        );
        for file in files {
            helix_file_decryptor.decrypt(file);
        }
        Ok(())
    }
}

#[test]
fn encryption_test() {
    let mut encryptor = HelixEncryptor::from("../test", "../test", "passphrase");
    encryptor.encrypt().unwrap();
}
