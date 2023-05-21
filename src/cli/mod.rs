use std::{path::PathBuf};
use crate::helix_crypto::core::HelixDecryptor;
use crate::helix_crypto::core::HelixEncryptor;
use clap::{command, Args, Parser, Subcommand};

use self::file::CliDecryptionObserverFactory;
use self::file::CliEncryptionObserverFactory;
pub mod file;


#[derive(Parser)]
#[command(name = "Helix")]
#[command(author = "Jaydev Rai <jaydev947@gmail.com>")]
#[command(version = "1.0.0")]
#[command(about = "Encyrpts and decrypts files", long_about = None)]
struct HelixCommand {
    #[command(subcommand)]
    subcommand: HelixSubCommand,
}

#[derive(Subcommand)]
enum HelixSubCommand {
    ///Encrypts the files from source directory and puts it in helix capsule
    Encrypt(EncryptArgs),
    ///Decrypts the files from helix capsule and puts it in target directory
    Decrypt(DecryptArgs),
}

#[derive(Args)]
struct EncryptArgs {
    ///The directory from where all files will be encrypted. Defaults to current working directory
    #[arg(short, long, value_name = "DIRECTORY")]
    source: Option<PathBuf>,

    ///The location of helix capsule. Defaults to current working directory
    #[arg(short, long, value_name = "DIRECTORY")]
    target: Option<PathBuf>,

    ///Delete the files from all source directory after encryption
    #[arg(short, long, default_value_t = false)]
    delete: bool,
}

#[derive(Args)]
struct DecryptArgs {
    ///The location of helix capsule. Defaults to current working directory
    #[arg(short, long, value_name = "DIRECTORY")]
    source: Option<PathBuf>,

    ///The location where all files will be decrypted. Defaults to current working directory
    #[arg(short, long, value_name = "DIRECTORY")]
    target: Option<PathBuf>,

    ///Delete the helix capsule after decryption
    #[arg(short, long, default_value_t = false)]
    delete: bool,
}

pub fn execute_helix_command() {
    let command = HelixCommand::parse();
    match command.subcommand {
        HelixSubCommand::Encrypt(enc_args) => encrypt(enc_args),
        HelixSubCommand::Decrypt(dec_args) => decrypt(dec_args),
    }
}

fn encrypt(enc_args: EncryptArgs) {
    let source = match enc_args.source {
        None => String::from("."),
        Some(e) => e.to_str().unwrap().to_owned(),
    };
    let destination = match enc_args.target {
        None => String::from("."),
        Some(e) => e.to_str().unwrap().to_owned(),
    };
    let passphrase = rpassword::prompt_password("Enter passphrase: ").unwrap();
    if !HelixEncryptor::has_helix_folder(&destination) {
        let confirm_passphrase = rpassword::prompt_password("Confirm passphrase: ").unwrap();
        if !confirm_passphrase.eq(&passphrase) {
            println!("Passphrase did not match. Try again!");
            return;
        }
    }
    let mut encryptor = HelixEncryptor::from(
        &source,
        &destination,
        &passphrase,
        &CliEncryptionObserverFactory,
    );
    if let Err(e) = encryptor.encrypt() {
        println!("Failed to encrypt, Reason : {}", e.message);
    }
}

fn decrypt(dec_args: DecryptArgs) {
    let source = match dec_args.source {
        None => String::from("."),
        Some(e) => e.to_str().unwrap().to_owned(),
    };
    let destination = match dec_args.target {
        None => String::from("."),
        Some(e) => e.to_str().unwrap().to_owned(),
    };
    let passphrase = rpassword::prompt_password("Enter passphrase: ").unwrap();
    let mut decryptor = HelixDecryptor::from(&source, &destination, &passphrase,&CliDecryptionObserverFactory);
    if let Err(e) = decryptor.decrypt() {
        println!("Failed to decrypt, Reason : {}", e.message);
    }
}
