use crate::{
    crypto::{
        chacha::{
            decryptors::ByteDecryptorImpl,
            keys::{Key, StorableKey},
        },
        ByteDecryptor,
    },
    util::hex::decode,
};

pub struct File {
    id: String,
    key: String,
    plain_hash: String,
    encrypted_hash: String,
    file_relative_path: String,
}

pub struct FileStore;

impl FileStore {
    pub fn get(self, id: &str) -> Option<File> {
        todo!()
    }

    pub fn search_plain_hash(self, plain_hash: &str) -> Option<File> {
        todo!()
    }

    pub fn store(self, file: File) {}
}

pub struct MasterKey {
    pub passphrase_digest: String,
    pub master_key: String,
}

pub struct MasterKeyStore;

impl MasterKeyStore {
    pub fn insert(self, master_key: MasterKey) {}

    fn update(self, master_key: MasterKey) {}

    pub fn get(self) -> MasterKey {
        todo!()
    }
}
