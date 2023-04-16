pub mod keys {
    use chacha20poly1305::{
        aead::{generic_array::GenericArray, OsRng},
        consts::{U12, U32},
        AeadCore, ChaCha20Poly1305, KeyInit,
    };
    use json::object;
    use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};
    use sha256::digest;

    use crate::{
        codecs::hex::{decode, decode_vec, encode, encode_vec},
        crypto::{ByteDecryptor, ByteEncryptor},
    };

    use super::{decryptors::ByteDecryptorImpl, encryptors::ByteEncryptorImpl};

    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;

    pub struct StorableKey {
        key: String,
        nonce: String,
    }

    pub struct KeyDecryptor<'a> {
        byte_decryptor: ByteDecryptorImpl<'a>,
    }

    impl<'a> KeyDecryptor<'a> {
        pub fn from(master_key: &'a Key) -> Self {
            let byte_decryptor = ByteDecryptorImpl::from(master_key);
            return KeyDecryptor { byte_decryptor };
        }

        pub fn decrypt(&self, key_string: String) -> Key {
            let key_json = json::from(key_string);
            let nonce_ge = {
                let nonce = key_json["nonce"].to_string();
                let mut nonce_bytes = [0u8; NONCE_SIZE];
                decode(nonce, &mut nonce_bytes);
                *GenericArray::from_slice(&nonce_bytes)
            };
            let key_ge = {
                let key = key_json["key"].to_string();
                let mut encrypted_key = decode_vec(key);
                self.byte_decryptor.decrypt(&mut encrypted_key);
                let key: [u8; KEY_SIZE] = encrypted_key.try_into().unwrap();
                *GenericArray::from_slice(&key)
            };
            Key {
                key: key_ge,
                nonce: nonce_ge,
            }
        }
    }

    pub struct KeyEncryptor<'a> {
        byte_encryptor: ByteEncryptorImpl<'a>,
    }

    impl<'a> KeyEncryptor<'a> {
        pub fn from(master_key: &'a Key) -> Self {
            let byte_encryptor = ByteEncryptorImpl::from(master_key);
            return KeyEncryptor { byte_encryptor };
        }

        pub fn encrypt(&self, key: &Key) -> String {
            let nonce_string = encode(&key.nonce);
            let mut vec = key.key.to_vec();
            self.byte_encryptor.encrypt(&mut vec);
            let key_string = encode_vec(vec);
            let ob = object! {
                key: key_string,
                nonce: nonce_string
            };
            ob.dump()
        }
    }

    pub struct Key {
        pub(super) key: GenericArray<u8, U32>,
        pub(super) nonce: GenericArray<u8, U12>,
    }

    impl Key {
        pub fn new() -> Self {
            Self::new_internal(&mut OsRng, &mut OsRng)
        }

        pub fn from_seed(seed: [u8; 32]) -> Self {
            // let digest = digest(input);
            // let mut digest_bytes = [0; 32];
            // decode(digest, &mut digest_bytes);
            let mut rng = StdRng::from_seed(seed);
            Self::new_internal(rng, &mut OsRng)
        }

        fn new_internal(
            key_rng: impl CryptoRng + RngCore,
            iv_rng: impl CryptoRng + RngCore,
        ) -> Self {
            let key = ChaCha20Poly1305::generate_key(key_rng);
            let nonce = ChaCha20Poly1305::generate_nonce(iv_rng);
            Self { key, nonce }
        }
    }
}

pub mod encryptors {

    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};

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

    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};

    use crate::crypto::ByteDecryptor;

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
        chacha::{decryptors::ByteDecryptorImpl, encryptors::ByteEncryptorImpl, keys::Key},
        ByteDecryptor, ByteEncryptor,
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
        print!("{:?}", data.len());
    }

    // #[test]
    // fn keygen_test() {
    //     let key = Key::from_seed(String::from("input"));
    //     print!("{:?}", key.key.len());
    //     print!("{:?}", key.nonce.len());
    // }
}
