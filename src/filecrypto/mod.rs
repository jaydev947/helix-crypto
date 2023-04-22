pub mod chacha;

pub trait FileEncryptor{
    fn encrypt(&self, source: &str, destination: &str);
}

pub trait FileDecryptor{
    fn decrypt(&self, source: &str, destination: &str);
}