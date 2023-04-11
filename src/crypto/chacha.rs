pub mod keys {
    use chacha20poly1305::{
        aead::{generic_array::GenericArray, OsRng},
        consts::{U12, U32},
        AeadCore, ChaCha20Poly1305, KeyInit,
    };

    pub struct Key {
        pub(super) key: GenericArray<u8, U32>,
        pub(super) nonce: GenericArray<u8, U12>,
    }

    impl Key {
        pub fn new() -> Self {
            let key = ChaCha20Poly1305::generate_key(&mut OsRng);
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            Self { key, nonce }
        }
    }
}

pub mod encryptors {

    use chacha20poly1305::{
        AeadInPlace, ChaCha20Poly1305, KeyInit,
    };

    use crate::crypto::ByteEncryptor;

    use super::keys::Key;

    pub struct ByteEncryptorImpl<'a> {
        key: &'a Key,
        cipher: ChaCha20Poly1305,
    }

    impl<'a> ByteEncryptorImpl<'a> {
        pub fn from(key: &'a Key) -> Self {
            Self {
                key,
                cipher: ChaCha20Poly1305::new(&key.key),
            }
        }
    }

    impl ByteEncryptor for ByteEncryptorImpl<'_> {
        fn encrypt(&self, buffer: &mut Vec<u8>) {
            self.cipher
                .encrypt_in_place(&self.key.nonce, b"", buffer)
                .unwrap();
        }
    }
}

pub mod decryptors {

    use chacha20poly1305::{
        AeadInPlace, ChaCha20Poly1305, KeyInit,
    };

    use crate::crypto::{ByteDecryptor};

    use super::keys::Key;

    pub struct ByteDecryptorImpl<'a> {
        key: &'a Key,
        cipher: ChaCha20Poly1305,
    }

    impl<'a> ByteDecryptorImpl<'a> {
        pub fn from(key: &'a Key) -> Self {
            Self {
                key,
                cipher: ChaCha20Poly1305::new(&key.key),
            }
        }
    }

    impl ByteDecryptor for ByteDecryptorImpl<'_> {
        fn decrypt(&self, buffer: &mut Vec<u8>) {
            self.cipher
                .decrypt_in_place(&self.key.nonce, b"", buffer)
                .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{
        ByteEncryptor,
        chacha::{encryptors::ByteEncryptorImpl, keys::Key, decryptors::ByteDecryptorImpl}, ByteDecryptor,
    };

    #[test]
    fn encryption_test() {
        let key = Key::new();
        let encryptor = ByteEncryptorImpl::from(&key);
        let decryptor = ByteDecryptorImpl::from(&key);
        let mut data = b"jdrm".to_vec();
        let res = encryptor.encrypt(&mut data);
        println!("{:?}", res);
        println!("{:?}", data.len());
        println!("{:?}", data);
        decryptor.decrypt(&mut data);
        print!("{:?}",data.len());
    }
}
