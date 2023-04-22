use std::path::Path;

use rand::Error;

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
    storage::{File, FileStore, MasterKey, MasterKeyStore},
    util::{
        hash::{hash_file, hash_string},
        hex::{decode, decode_vec, encode_vec},
        uuid::generate,
    },
};

pub struct MasterKeyManager<'a> {
    master_key_store: MasterKeyStore<'a>,
}

impl MasterKeyManager<'_> {
    pub fn generate(self, passphrase: String) -> Key {
        let passphrase_ref = passphrase.as_str();
        let passphrase_digest = hash_string(passphrase_ref);
        let passphrase_key = Self::get_passphrase_key(passphrase_ref, &passphrase_digest);
        let key_encryptor = KeyEncryptor::from(&passphrase_key);
        let master_key_plain = Key::new();
        let master_key = key_encryptor.encrypt(&master_key_plain);
        self.master_key_store.insert(MasterKey {
            passphrase_digest,
            master_key,
        });
        master_key_plain
    }

    pub fn get(self, passphrase: String) -> Key {
        let passphrase_ref = passphrase.as_str();
        let passphrase_digest = hash_string(passphrase_ref);
        let master_key = self.master_key_store.get();
        if !master_key.passphrase_digest.eq(&passphrase_digest) {
            panic!("incorrect passphrase");
        }
        let key = Self::get_passphrase_key(passphrase_ref, &passphrase_digest);
        let key_decryptor = KeyDecryptor::from(&key);
        key_decryptor.decrypt(&master_key.master_key)
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

struct HelixFileEncryptor<'a> {
    block_folder: &'a str,
    file_store: FileStore<'a>,
    key_encryptor: KeyEncryptor<'a>,
    byte_encryptor: ByteEncryptorImpl<'a>,
}

impl HelixFileEncryptor<'_> {
    pub fn encrypt(&self, file_path: &str) {
        let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
        let file_id = hash_string(file_name);
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
        let plain_hash = hash_file(file_path);
        let encrypted_hash = hash_file(&encrypted_file_path);
        let encrypted_key = self.key_encryptor.encrypt(&file_key);
        let encrypted_file_path = Self::encrypt_filepath(&file_key, file_path);
        File {
            id: String::from(file_id),
            plain_hash: plain_hash,
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

struct HelixFileDecryptor<'a> {
    source_folder: &'a str,
    block_folder: &'a str,
    file_store: FileStore<'a>,
    key_decryptor: KeyDecryptor<'a>,
    byte_decryptor: ByteDecryptorImpl<'a>,
}

impl HelixFileDecryptor<'_> {
    fn decrypt(&self, file: File) {
        let encrypted_file_path = self.get_block_path(&file.id);
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

    fn get_block_path(&self, file_id: &str) -> String {
        let binding = Path::new(self.block_folder).join(file_id);
        let path = binding.to_str().unwrap();
        String::from(path)
    }
}
