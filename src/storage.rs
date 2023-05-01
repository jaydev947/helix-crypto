use std::error::Error;

use rusqlite::{params, Connection, Result};

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

type FileTuple = (String, String, String, String, String);

impl<'a> FileStore<'a> {
    pub fn from(connection: &'a Connection) -> Self {
        Self { connection }
    }

    pub fn get_all(&self) -> Vec<File> {
        let query = "SELECT * FROM files";
        let mut stmt = self.connection.prepare(query).unwrap();
        let files = stmt
            .query_map([], |row| {
                Ok(File {
                    id: row.get(0)?,
                    key: row.get(1)?,
                    plain_hash: row.get(2)?,
                    encrypted_hash: row.get(3)?,
                    file_path: row.get(4)?,
                })
            })
            .unwrap();
        let actual = files.map(|data| data.unwrap());
        Vec::from_iter(actual)
    }

    pub fn get(&self, id: &str) -> Option<File> {
        let query = "SELECT * FROM files where id = ?1";
        let mut stmt = self.connection.prepare(query).unwrap();
        let mut files = stmt
            .query_map([id], |row| {
                Ok(File {
                    id: String::from(id),
                    key: row.get(1)?,
                    plain_hash: row.get(2)?,
                    encrypted_hash: row.get(3)?,
                    file_path: row.get(4)?,
                })
            })
            .unwrap();
        match files.next() {
            Some(data) => Some(data.unwrap()),
            None => None,
        }
    }

    pub fn store(&self, file: File) {
        let query = "INSERT INTO files values(?1,?2,?3,?4,?5)";
        let params: FileTuple = (
            file.id,
            file.key,
            file.plain_hash,
            file.encrypted_hash,
            file.file_path,
        );
        self.connection.execute(query, params).unwrap();
    }

    pub fn update(&self, file: File) {
        let query = "UPDATE files SET key = ?2,
         plain_hash = ?3, 
         encrypted_hash = ?4,
         file_path = ?5
         where id = ?1";
        let params: FileTuple = (
            file.id,
            file.key,
            file.plain_hash,
            file.encrypted_hash,
            file.file_path,
        );
        self.connection.execute(query, params).unwrap();
    }
}

#[derive(Debug)]
pub struct MasterKey {
    pub passphrase_digest: String,
    pub master_key: String,
}

pub struct MasterKeyStore<'a> {
    connection: &'a Connection,
}

impl<'a> MasterKeyStore<'a> {
    pub fn from(connection: &'a Connection) -> Self {
        Self { connection }
    }

    pub fn insert(&self, master_key: MasterKey) {
        let query = "INSERT INTO master_key values(?1,?2,?3)";
        let params = (1, master_key.passphrase_digest, master_key.master_key);
        self.connection.execute(query, params).unwrap();
    }

    fn update(self, master_key: MasterKey) {
        let query = "UPDATE master_key SET passphrase_hash = ?2, master_key = ?3 where id = ?1";
        let params = (1, master_key.passphrase_digest, master_key.master_key);
        self.connection.execute(query, params).unwrap();
    }

    pub fn get(self) -> Option<MasterKey> {
        let query = "SELECT * FROM master_key where id = ?1";
        let mut stmt = self.connection.prepare(query).unwrap();
        let mut master_keys = stmt
            .query_map([1], |row| {
                Ok(MasterKey {
                    passphrase_digest: row.get(1)?,
                    master_key: row.get(2)?,
                })
            })
            .unwrap();
        match master_keys.next() {
            Some(res) => Some(res.unwrap()),
            None => None,
        }
    }
}

pub mod schema {
    use rusqlite::Connection;

    const MASTER_KEY: &str = "CREATE TABLE IF NOT EXISTS master_key (
        id INTEGER NOT NULL PRIMARY KEY,
        passphrase_hash TEXT NOT NULL,
        master_key TEXT NOT NULL);";

    const FILES: &str = "CREATE TABLE IF NOT EXISTS files (
        id TEXT NOT NULL PRIMARY KEY, 
        key TEXT NOT NULL,
        plain_hash TEXT NOT NULL,
        encrypted_hash TEXT NOT NULL,
        file_path TEXT NOT NULL);";

    pub struct HelixSchemaCreator;

    impl HelixSchemaCreator {
        pub fn create(connection: &Connection) {
            connection.execute(MASTER_KEY, ()).unwrap();
            connection.execute(FILES, ()).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::{schema::HelixSchemaCreator, MasterKeyStore};

    #[test]
    fn create_schema_test() {
        let connection = Connection::open("../test.db").unwrap();
        HelixSchemaCreator::create(&connection);
    }

    #[test]
    fn insert_master_key() {
        let connection = Connection::open("../test.db").unwrap();
        let store = MasterKeyStore::from(&connection);
        store.insert(super::MasterKey {
            passphrase_digest: String::from("hello"),
            master_key: String::from("world"),
        });
    }

    #[test]
    fn get_master_key() {
        let connection = Connection::open("../test.db").unwrap();
        let store = MasterKeyStore::from(&connection);
        let master_key = store.get();
        print!("{:?}", master_key)
    }
}
