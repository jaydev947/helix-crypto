mod chacha;

pub trait FileEncryptor{
    fn encrypt(&self, source: String, destination: String);
}

pub trait FileDecryptor{
    fn decrypt(&self, source: String, destination: String);
}