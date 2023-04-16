use crate::{
    codecs::hex::decode,
    crypto::{
        chacha::{
            decryptors::ByteDecryptorImpl,
            keys::{Key, StorableKey},
        },
        ByteDecryptor,
    },
};

struct File {
    id: String,
    key: String,
    plain_hash: String,
    encrypted_hash: String,
    file_relative_path: String,
}

struct FileStore {}

impl FileStore {
    fn get(id: String) -> File {
        todo!()
    }

    fn store(file: File) {}
}

pub struct MasterKey {
    pub passphrase_digest: String,
    pub master_key: String,
}

pub struct MasterKeyStore;

impl MasterKeyStore {
    pub fn insert(self, master_key: MasterKey) {}

    fn update(self, master_key: MasterKey) {}

    pub fn get(self ) -> MasterKey {
        todo!()
    }
}
