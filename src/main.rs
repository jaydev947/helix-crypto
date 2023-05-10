use std::{
    env,
    path::{Path, PathBuf},
};

use crate::observer::EventImpl;
use cli::execute_helix_command;
mod cli;
mod crypto;
pub mod errors;
mod filecrypto;
mod fileio;
mod helix_crypto;
mod observer;
mod storage;
mod util;

fn main() {
    execute_helix_command();
}

