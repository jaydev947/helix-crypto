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

pub(super) struct HelixFileEncryptor<'a> {
    block_folder: &'a str,
    file_store: FileStore<'a>,
    key_encryptor: KeyEncryptor<'a>,
    byte_encryptor: ByteEncryptorImpl<'a>,
}

impl<'a> HelixFileEncryptor<'a> {
    pub(super) fn from(
        block_folder: &'a str,
        master_key: &'a Key,
        connection: &'a Connection,
    ) -> Self {
        Self {
            block_folder,
            file_store: FileStore::from(connection),
            key_encryptor: KeyEncryptor::from(master_key),
            byte_encryptor: ByteEncryptorImpl::from(master_key),
        }
    }

    pub(super) fn encrypt(&self, file_path: &str) {
        let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
        let file_id = hash_string(file_name);
        print!(" file name {} hashed to {}",file_name,file_id);
        let file_option = self.file_store.get(&file_id);
        match file_option {
            None => self.create_file(file_path, &file_id),
            Some(file) => self.update_file(file_path, &file_id, &file),
        };
    }

    fn create_file(&self, file_path: &str, file_id: &str) {
        let plain_hash = hash_file(file_path);
        let file = self.encrypt_internal(file_path, file_id, &plain_hash);
        self.file_store.store(file);
    }

    fn encrypt_internal(&self, file_path: &str, file_id: &str, plain_hash: &str) -> File {
        let file_key = Key::new();
        let file_encryptor = CCFileEncryptor::from(&file_key);
        let encrypted_file_path = self.get_block_path(file_id);
        file_encryptor.encrypt(file_path, &encrypted_file_path);
        let encrypted_hash = hash_file(&encrypted_file_path);
        let encrypted_key = self.key_encryptor.encrypt(&file_key);
        let encrypted_file_path = Self::encrypt_filepath(&file_key, file_path);
        File {
            id: String::from(file_id),
            plain_hash: String::from(plain_hash),
            encrypted_hash: encrypted_hash,
            key: encrypted_key,
            file_path: encrypted_file_path,
        }
    }

    fn get_block_path(&self, file_id: &str) -> String {
        let binding = Path::new(self.block_folder).join(file_id);
        let path = binding.to_str().unwrap();
        String::from(path)
    }

    fn encrypt_filepath(key: &Key, file_path: &str) -> String {
        let mut vec = Vec::from(file_path.as_bytes());
        let encryptor = ByteEncryptorImpl::from(key);
        encryptor.encrypt(&mut vec);
        encode_vec(vec)
    }

    fn update_file(&self, file_path: &str, file_id: &str, file: &File) {
        let current_hash = hash_file(file_path);
        if current_hash.eq(&file.plain_hash) {
            if self.encrypted_file_unchanged(file_id, &file.encrypted_hash) {
                return;
            }
        }
        let file = self.encrypt_internal(file_path, file_id, &current_hash);
        self.file_store.update(file);
    }

    fn encrypted_file_unchanged(&self, file_id: &str, encrypted_hash: &str) -> bool {
        let encrypted_path = self.get_block_path(file_id);
        if Path::new(&encrypted_path).exists() {
            let current_hash = hash_file(&encrypted_path);
            return encrypted_hash.eq(&current_hash);
        } else {
            return false;
        }
    }
}

pub(super) struct HelixFileDecryptor<'a> {
    block_folder: &'a str,
    file_store: FileStore<'a>,
    key_decryptor: KeyDecryptor<'a>,
    byte_decryptor: ByteDecryptorImpl<'a>,
}

impl<'a> HelixFileDecryptor<'a> {
    pub(super) fn from(
        block_folder: &'a str,
        master_key: &'a Key,
        connection: &'a Connection,
    ) -> Self {
        Self {
            block_folder,
            file_store: FileStore::from(connection),
            key_decryptor: KeyDecryptor::from(master_key),
            byte_decryptor: ByteDecryptorImpl::from(master_key),
        }
    }

    pub(super) fn decrypt(&self, file: File) {
        let encrypted_file_path = self.get_encrypted_file_path(&file.id);
        if Self::encrypted_block_changed(&encrypted_file_path, &file.encrypted_hash) {
            return;
        }
        let key = self.key_decryptor.decrypt(&file.key);
        let plain_file_path = Self::decrypt_filepath(&key, &file.file_path);
        let file_decryptor = CCFileDecryptor::from(&key);
        file_decryptor.decrypt(&encrypted_file_path, &plain_file_path);
    }

    fn decrypt_filepath(key: &Key, file_path: &str) -> String {
        let mut decoded = decode_vec(file_path);
        let decryptor = ByteDecryptorImpl::from(key);
        decryptor.decrypt(&mut decoded);
        String::from_utf8(decoded).unwrap()
    }

    fn encrypted_block_changed(file_path: &str, file_hash: &str) -> bool {
        if !Path::new(file_path).exists() {
            return true;
        }
        let current_hash = hash_file(file_path);
        if !current_hash.eq(file_hash) {
            return true;
        }
        return false;
    }

    fn get_encrypted_file_path(&self, file_id: &str) -> String {
        let binding = Path::new(self.block_folder).join(file_id);
        let path = binding.to_str().unwrap();
        String::from(path)
    }
}
