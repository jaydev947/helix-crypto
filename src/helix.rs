use rand::Error;
use sha256::digest;

use crate::{
    codecs::hex::decode,
    crypto::chacha::keys::{Key, KeyDecryptor, KeyEncryptor},
    storage::{MasterKey, MasterKeyStore},
};

pub struct MasterKeyManager {
    master_key_store: MasterKeyStore,
}

impl MasterKeyManager {
    
    pub fn generate(self, passphrase: String) -> Key {
        let passphrase_ref = passphrase.as_str();
        let passphrase_digest = digest(passphrase_ref);
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
        let passphrase_digest = digest(passphrase_ref);
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
        let final_digest = Self::string_digest(&final_digest_str);
        let passphrase_key = Key::from_seed(final_digest);
        passphrase_key
    }

    fn string_digest(passphrase: &str) -> [u8; 32] {
        let digest = digest(passphrase);
        let mut digest_bytes = [0; 32];
        decode(digest, &mut digest_bytes);
        digest_bytes
    }
}
