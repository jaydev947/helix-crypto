pub mod chacha;

pub trait FileEncryptor{
    fn encrypt(&mut self, source: &str, destination: &str);
}

pub trait FileDecryptor{
    fn decrypt(&mut self, source: &str, destination: &str);
}