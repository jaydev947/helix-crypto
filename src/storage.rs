use sqlite::{Connection, Value};

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
    pub id: String, //hash of path only. PK. No other indentifier.
    pub key: String,
    pub plain_hash: String,     //for reencryption
    pub encrypted_hash: String, //for integrity check as well as encryption duplication test
    pub file_path: String,      //for decryption
}

pub struct FileStore<'a> {
    connection: &'a Connection,
}

impl Clone for FileStore<'_> {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection,
        }
    }
}

impl Copy for FileStore<'_> {}

impl FileStore<'_> {
    pub fn get(&self, id: &str) -> Option<File> {
        todo!()
    }

    pub fn search_plain_hash(self, plain_hash: &str) -> Option<File> {
        todo!()
    }

    pub fn store(self, file: File) {}

    pub fn update(self, file: File) {}
}

pub struct MasterKey {
    pub passphrase_digest: String,
    pub master_key: String,
}

pub struct MasterKeyStore<'a> {
    connection: &'a Connection,
}

impl MasterKeyStore<'_> {
    pub fn insert(&self, master_key: MasterKey) {
        let query = "INSERT INTO master_key values(:id,:passphrase_hash,:master_key)";
        let mut statement = self.connection.prepare(query).unwrap();
        Self::bind(statement, master_key);
    }

    fn update(self, master_key: MasterKey) {
        let query = "UPDATE master_key SET passphrase_hash = :passphrase_hash, master_key = :master_key where id = :id";
        let mut statement = self.connection.prepare(query).unwrap();
        Self::bind(statement, master_key);
    }

    fn bind(mut statement: sqlite::Statement, master_key: MasterKey) {
        statement
            .bind::<&[(_, Value)]>(&[
                (":id", 1.into()),
                (
                    ":passphrase_hash",
                    master_key.passphrase_digest.as_str().into(),
                ),
                (":master_key", master_key.master_key.as_str().into()),
            ])
            .unwrap();
    }

    pub fn get(self) -> MasterKey {
        todo!()
    }
}

pub mod schema {

    use sqlite::Connection;

    const MASTER_KEY: &str = "CREATE TABLE master_key (
        id INTEGER NOT NULL PRIMARY KEY,
        passphrase_hash TEXT NOT NULL,
        master_key TEXT NOT NULL);";

    const FILES: &str = "CREATE TABLE files (
        id TEXT NOT NULL PRIMARY KEY, 
        key TEXT NOT NULL,
        plain_hash TEXT NOT NULL,
        encrypted_hash TEXT NOT NULL,
        file_path TEXT NOT NULL);";

    pub struct HelixSchemaCreator;

    impl HelixSchemaCreator {
        pub fn create(connection: &Connection) {
            connection.execute(MASTER_KEY).unwrap();
            connection.execute(FILES).unwrap();
        }
    }
}
