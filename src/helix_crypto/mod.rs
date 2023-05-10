use crate::errors::HelixError;

use self::{
    core::{HelixDecryptor, HelixEncryptor},
};

pub mod core;
mod files;
pub mod folder_walker;
mod master_key;

// #[allow(dead_code)]
// pub fn encrypt<'a>(
//     source: &'a str,
//     destination: &'a str,
//     passphrase: &'a str,
// ) -> Result<(), HelixError> {
//     let mut encryptor = HelixEncryptor::from(source, destination, passphrase);
//     encryptor.encrypt()
// }

// #[allow(dead_code)]
// pub fn decrypt<'a>(
//     source: &'a str,
//     destination: &'a str,
//     passphrase: &'a str,
// ) -> Result<(), HelixError> {
//     let mut decryptor = HelixDecryptor::from(source, destination, passphrase);
//     decryptor.decrypt()
// }
