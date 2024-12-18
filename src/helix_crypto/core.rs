use std::{
    fs::{self, create_dir_all},
    io,
    path::{Path, PathBuf},
};

use rusqlite::Connection;

use crate::{
    cli::file::{
        CliDecryptionObserverFactory, CliEncryptionObserverFactory, DecryptionObserverFactory,
        EncryptionObserverFactory,
    },
    crypto::chacha::keys::Key,
    errors::HelixError,
    storage::{schema::HelixSchemaCreator, FileStore},
};

use super::{
    files::{HelixFileDecryptor, HelixFileEncryptor},
    folder_walker::get_files,
    master_key::MasterKeyManager,
};

struct HelixState {
    connection: Connection,
    master_key: Key,
    block_directory: PathBuf,
}
pub struct HelixEncryptor<'a> {
    source: &'a str,
    destination: &'a str,
    passphrase: &'a str,
    helix_state: Option<HelixState>,
    encryption_observer_factory: &'a dyn EncryptionObserverFactory,
    delete: bool
}

const CAP: u32 = 1024 * 1024 * 2;

impl<'a> HelixEncryptor<'a> {
    pub fn from(
        source: &'a str,
        destination: &'a str,
        passphrase: &'a str,
        encryption_observer_factory: &'a impl EncryptionObserverFactory,
        delete: bool
    ) -> Self {
        Self {
            source,
            destination,
            passphrase,
            helix_state: None,
            encryption_observer_factory,
            delete
        }
    }

    pub fn has_helix_folder(folder: &str) -> bool {
        let path = Path::new(folder).join(".helix");
        path.exists()
    }

    fn check_helix_setup(&mut self) -> Result<(), HelixError> {
        if self.helix_state.is_some() {
            return Ok(());
        }
        let destination_path = Path::new(self.destination);
        let helix_folder = destination_path.join(".helix");
        let db_file_path = helix_folder.join("metadata.db");
        let block_path = helix_folder.join("blocks");
        create_dir_all(&block_path).unwrap();
        let connection = Connection::open(db_file_path).unwrap();
        HelixSchemaCreator::create(&connection);
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
        let master_key = match master_key_manager.get(self.passphrase)? {
            Some(key) => key,
            None => master_key_manager.generate(self.passphrase),
        };
        Ok(master_key)
    }

    pub fn encrypt(&mut self) -> Result<(), HelixError> {
        self.check_helix_setup()?;
        let paths = get_files(self.source);
        if paths.len() == 0 {
            return Ok(());
        }
        let state = self.helix_state.as_ref().unwrap();
        let helix_encryptor = HelixFileEncryptor::from(
            self.source,
            state.block_directory.to_str().unwrap(),
            &state.master_key,
            &state.connection,
            CAP,
        );
        for path in paths {
            let path_str = path.to_str().unwrap();
            let size = fs::metadata(path.clone()).unwrap().len();
            let mut observer = self.encryption_observer_factory.create(path.clone(), size);
            helix_encryptor.encrypt(path_str, &mut *observer);
            if self.delete{
                fs::remove_file(path);
            }
        }
       
        Ok(())
    }
}

fn delete_empty_directories_recursively(directory_path: &str) -> io::Result<()> {
    if let Ok(entries) = fs::read_dir(directory_path) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    delete_empty_directories_recursively(&path.to_str().unwrap())?;
                    if fs::read_dir(&path)?.next().is_none() {
                        fs::remove_dir(&path)?;
                    }
                }
            }
        }
    }

    Ok(())
}

pub(crate) struct HelixDecryptor<'a> {
    source: &'a str,
    destination: &'a str,
    passphrase: &'a str,
    helix_state: Option<HelixState>,
    decryption_observer_factory: &'a dyn DecryptionObserverFactory,
}

impl<'a> HelixDecryptor<'a> {
    pub fn from(
        source: &'a str,
        destination: &'a str,
        passphrase: &'a str,
        decryption_observer_factory: &'a dyn DecryptionObserverFactory,
    ) -> Self {
        Self {
            source,
            destination,
            passphrase,
            helix_state: None,
            decryption_observer_factory,
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
                "InvalidHelixCapsule",
                "NoHelixFolder",
                ".helix folder not found",
            ));
        }
        let db_file_path = helix_folder.join("metadata.db");
        if !db_file_path.exists() {
            return Err(HelixError::from(
                "InvalidHelixCapsule",
                "NoDBFile",
                "metadata.db file not found",
            ));
        }
        let block_path = helix_folder.join("blocks");
        if !block_path.exists() {
            return Err(HelixError::from(
                "InvalidHelixCapsule",
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
                "InvalidHelixCapsule",
                "NoMasterKey",
                "Master Key not found in db",
            )),
        }
    }

    pub fn decrypt(&mut self) -> Result<(), HelixError> {
        self.check_helix_setup()?;
        let state = self.helix_state.as_ref().unwrap();
        let file_store = FileStore::from(&state.connection);
        let files = file_store.get_all();
        if files.len() == 0 {
            return Ok(());
        }
        let helix_file_decryptor = HelixFileDecryptor::from(
            self.destination,
            state.block_directory.to_str().unwrap(),
            &state.master_key,
            self.decryption_observer_factory,
        );
        for file in files {
            helix_file_decryptor.decrypt(file);
        }
        Ok(())
    }
}

#[test]
fn encryption_test() {
    let mut encryptor = HelixEncryptor::from(
        "../test",
        "../test",
        "passphrase",
        &CliEncryptionObserverFactory,
        true,
    );
    encryptor.encrypt().unwrap();
}

#[test]
fn decryption_test() {
    let mut decryptor = HelixDecryptor::from(
        "../test",
        "../test",
        "passphrase",
        &CliDecryptionObserverFactory,
    );
    decryptor.decrypt().unwrap();
}
