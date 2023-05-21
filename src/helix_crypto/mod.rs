use crate::errors::HelixError;

use self::{
    core::{HelixDecryptor, HelixEncryptor},
};

pub mod core;
mod files;
pub mod folder_walker;
mod master_key;