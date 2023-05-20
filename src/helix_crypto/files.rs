use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
};

use rand::Error;
use rusqlite::Connection;

use crate::{
    cli::file::{EncryptionObserver, ValidationStates},
    crypto::{
        chacha::{
            decryptors::ByteDecryptorImpl,
            encryptors::ByteEncryptorImpl,
            keys::{Key, KeyDecryptor, KeyEncryptor},
        },
        ByteDecryptor, ByteEncryptor,
    },
    filecrypto::{
        chacha::{
            decryptors::CCFileDecryptor,
            encryptors::{CCFileEncryptor, ChunkObserver},
        },
        FileDecryptor, FileEncryptor,
    },
    storage::{schema::HelixSchemaCreator, File, FileStore, MasterKey, MasterKeyStore},
    util::{
        hash::{hash_file, hash_string},
        hex::{decode, decode_vec, encode_vec},
        uuid::generate,
    },
};

struct ChunkObserverWrapper<'a> {
    encryption_observer: &'a dyn EncryptionObserver,
}

impl ChunkObserver for ChunkObserverWrapper<'_> {
    fn chunk_encrypted(&self, chunk_number: u32) {
        self.encryption_observer.update_chunk_encrypted(chunk_number);
    }
}

pub(super) struct HelixFileEncryptor<'a> {
    source_folder: &'a str,
    block_folder: &'a str,
    file_store: FileStore<'a>,
    key_encryptor: KeyEncryptor<'a>,
    chunk_size: u32,
}

impl<'a> HelixFileEncryptor<'a> {
    pub(super) fn from(
        source_folder: &'a str,
        block_folder: &'a str,
        master_key: &'a Key,
        connection: &'a Connection,
        chunk_size: u32,
    ) -> Self {
        Self {
            source_folder,
            block_folder,
            file_store: FileStore::from(connection),
            key_encryptor: KeyEncryptor::from(master_key),
            chunk_size,
        }
    }

    pub(super) fn encrypt(&self, file_path: &str, observer: &dyn EncryptionObserver) {
        let file_id = hash_string(file_path);
        let file_option = self.file_store.get(&file_id);
        match file_option {
            None => self.create_file(file_path, &file_id, observer),
            Some(file) => self.update_file(file_path, &file_id, &file, observer),
        };
    }

    fn create_file(&self, file_path: &str, file_id: &str, observer: &dyn EncryptionObserver) {
        observer.update_state(ValidationStates::PlainFileCheck);
        let plain_hash = hash_file(file_path);
        let file = self.encrypt_internal(file_path, file_id, &plain_hash, observer);
        self.file_store.store(file);
    }

    fn encrypt_internal(
        &self,
        file_path: &str,
        file_id: &str,
        plain_hash: &str,
        observer: &dyn EncryptionObserver,
    ) -> File {
        let chunk_observer = ChunkObserverWrapper {
            encryption_observer: observer,
        };
        let file_key = Key::new();
        let file_encryptor = CCFileEncryptor::from(&file_key, self.chunk_size, &chunk_observer);
        let block_path = self.get_block_path(file_id);
        file_encryptor.encrypt(file_path, &block_path);
        let encrypted_hash = hash_file(&block_path);
        let encrypted_key = self.key_encryptor.encrypt(&file_key);
        let stripped_path = self.strip_source(file_path);
        let encrypted_file_path = Self::encrypt_filepath(&file_key, stripped_path);
        File {
            id: String::from(file_id),
            plain_hash: String::from(plain_hash),
            encrypted_hash: encrypted_hash,
            key: encrypted_key,
            file_path: encrypted_file_path,
        }
    }

    fn strip_source(&self, file_path: &'a str) -> &'a str {
        let source = Path::new(self.source_folder);
        let file = Path::new(file_path);
        file.strip_prefix(source).unwrap().to_str().unwrap()
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

    fn update_file(
        &self,
        file_path: &str,
        file_id: &str,
        file: &File,
        observer: &dyn EncryptionObserver,
    ) {
        let current_hash = hash_file(file_path);
        if current_hash.eq(&file.plain_hash) {
            observer.update_state(ValidationStates::EncryptedBlockCheck);
            if self.encrypted_file_unchanged(file_id, &file.encrypted_hash) {
                observer.update_state(ValidationStates::Unchanged);
                return;
            }
        }
        let file = self.encrypt_internal(file_path, file_id, &current_hash, observer);
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
    destination: &'a str,
    block_folder: &'a str,
    key_decryptor: KeyDecryptor<'a>,
}

impl<'a> HelixFileDecryptor<'a> {
    pub(super) fn from(destination: &'a str, block_folder: &'a str, master_key: &'a Key) -> Self {
        Self {
            destination,
            block_folder,
            key_decryptor: KeyDecryptor::from(master_key),
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
        let complete_path = self.append_destination(plain_file_path);
        file_decryptor.decrypt(&encrypted_file_path, &complete_path);
    }

    fn append_destination(&self, plain_file_path: String) -> String {
        Path::new(self.destination)
            .join(plain_file_path)
            .to_str()
            .unwrap()
            .to_owned()
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

#[test]
fn source_striper() {
    let source = Path::new(".").to_path_buf();
    let child = Path::new(".").join("mid").join("hello.txt");
    let stripped = child.strip_prefix(source).unwrap();
    println!("{:?}", stripped)
}
