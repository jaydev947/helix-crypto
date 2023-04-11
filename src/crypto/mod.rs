pub mod chacha;

pub trait ByteEncryptor {
    fn encrypt(&self, plain: &mut Vec<u8>);
}

pub trait ByteDecryptor {
    fn decrypt(&self, cipher: &mut Vec<u8>);
}
