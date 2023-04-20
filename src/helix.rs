use std::path::Path;

use rand::Error;

use crate::{
    crypto::chacha::keys::{Key, KeyDecryptor, KeyEncryptor},
    storage::{File, FileStore, MasterKey, MasterKeyStore},
    util::{hash::hash_string, hex::decode, uuid::generate},
};

pub struct MasterKeyManager {
    master_key_store: MasterKeyStore,
}

impl MasterKeyManager {
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
        key_decryptor.decrypt(master_key.master_key)
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

struct FileEncryptor<'a> {
    destination_folder: String,
    file_store: &'a FileStore,
}

impl FileEncryptor<'_> {
    fn encrypt(&self, file_path: &str) {
        let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
        let file_id = hash_string(file_name);
        let file_option = self.file_store.get(&file_id);
        match file_option{
            None => Self::create_file(file_path,file_name,&file_id),
            Some(file)=>Self::update_file(&file)
        };
    }

    fn create_file(file_path:&str, file_name:&str,file_id:&str){

    }

    fn update_file(file: &File) {}
}
