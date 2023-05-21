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
    errors::HelixError,
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

pub(super) struct MasterKeyManager<'a> {
    connection: &'a Connection,
}

impl<'a> MasterKeyManager<'a> {
    pub(super) fn from(connection: &'a Connection) -> Self {
        Self { connection }
    }

    pub(super) fn generate(&self, passphrase: &'a str) -> Key {
        let passphrase_digest = hash_string(passphrase);
        let passphrase_key = Self::get_passphrase_key(passphrase, &passphrase_digest);
        let key_encryptor = KeyEncryptor::from(&passphrase_key);
        let master_key_plain = Key::new();
        let master_key = key_encryptor.encrypt(&master_key_plain);
        let master_key_store = MasterKeyStore::from(self.connection);
        master_key_store.insert(MasterKey {
            passphrase_digest,
            master_key,
        });
        master_key_plain
    }

    pub fn get(&self, passphrase: &'a str) -> Result<Option<Key>, HelixError> {
        let passphrase_digest = hash_string(passphrase);
        let master_key_store = MasterKeyStore::from(self.connection);
        match master_key_store.get() {
            Some(master_key) => {
                if !master_key.passphrase_digest.eq(&passphrase_digest) {
                    return Err(HelixError::from(
                        "BadInput",
                        "PassphraseMismatch",
                        "Provided passphrase does not match with the initially entered passphrase.",
                    ));
                }
                let key = Self::get_passphrase_key(passphrase, &passphrase_digest);
                let key_decryptor = KeyDecryptor::from(&key);
                let decrypted = key_decryptor.decrypt(&master_key.master_key);
                Ok(Some(decrypted))
            }
            None => Ok(None),
        }
    }

    fn get_passphrase_key(passphrase: &str, passphrase_digest: &str) -> Key {
        let final_digest_str = format!("{}{}", passphrase, passphrase_digest);
        let final_digest = Self::get_hash_bytes(&final_digest_str);
        let passphrase_key = Key::from_seed(final_digest);
        passphrase_key
    }

    fn get_hash_bytes(passphrase: &str) -> [u8; 32] {
        let digest = hash_string(passphrase);
        let mut digest_bytes = [0; 32];
        decode(digest, &mut digest_bytes);
        digest_bytes
    }
}

#[test]
fn create_schema_test() {
    let connection = Connection::open("../test.db").unwrap();
    HelixSchemaCreator::create(&connection);
}

#[test]
fn generate_test() {
    let connection = Connection::open("../test.db").unwrap();
    let manager = MasterKeyManager::from(&connection);
    let key = manager.generate("passphrase");
}

#[test]
fn get_test() {
    let connection = Connection::open("../test.db").unwrap();
    let manager = MasterKeyManager::from(&connection);
    let key = manager.get("passphrase");
}
