pub mod encryptors{
    use crate::{
        crypto::{chacha::{encryptors::ByteEncryptorImpl, keys::Key}, ByteEncryptor}, fileio::{readers::FileReader, writers::{FileWriter, ChunkWriter}}, filecrypto::FileEncryptor,
    };
    
    pub struct CCFileEncryptor<'a> {
        key: &'a Key,
    }

    impl<'a> CCFileEncryptor<'a> {
        pub fn from(key: &'a Key) -> Self {
            Self { key }
        }
    }

    const CAP: u32 = 1024 * 1024 * 2;
    
    impl<'a> FileEncryptor for CCFileEncryptor<'a> {

        fn encrypt(&self, source: &str, destination: &str) {
            let byte_encryptor = ByteEncryptorImpl::from(&self.key);
            let mut reader = FileReader::from(CAP,source);
            let mut writer = ChunkWriter::from(destination);
            let mut data = reader.next();
            while let Some(mut buffer) = data {
                byte_encryptor.encrypt(&mut buffer);
                writer.write(buffer);
                data = reader.next();
            }
            writer.close();
        }
    }
    
}

pub mod decryptors{

    use crate::{
        crypto::{chacha::{keys::Key, decryptors::ByteDecryptorImpl}, ByteDecryptor}, fileio::{readers::{ChunkReader}, writers::FileWriter}, filecrypto::{FileDecryptor},
    };
    
    pub struct CCFileDecryptor<'a> {
        key: &'a Key,
    }

    impl<'a> CCFileDecryptor<'a> {
        pub fn from(key: &'a Key) -> Self {
            Self { key }
        }
    }
    
    impl<'a> FileDecryptor for CCFileDecryptor<'a> {
        
        fn decrypt(&self, source: &str, destination: &str) {
            let byte_encryptor = ByteDecryptorImpl::from(&self.key);
            let mut reader = ChunkReader::from(source);
            let mut writer = FileWriter::from(destination);
            let mut data = reader.next();
            while let Some(mut buffer) = data {
                byte_encryptor.decrypt(&mut buffer);
                writer.write(buffer);
                data = reader.next();
            }
            writer.close();
        }
    }

}

#[cfg(test)]
    mod tests {
        use crate::{crypto::chacha::keys::Key, filecrypto::{chacha::{encryptors::CCFileEncryptor, decryptors::CCFileDecryptor}, FileEncryptor, FileDecryptor}};
    
        #[test]
        fn file_encrypt_decrypt_test() {
            let key = Key::new();
            let encryptor = CCFileEncryptor::from(&key);
            // let source = String::from("D:\\Other\\Badhaai Do (2022) [1080p] [WEBRip] [5.1] [YTS.MX]\\Badhaai.Do.2022.1080p.WEBRip.x264.AAC5.1-[YTS.MX].mp4");
            let source = String::from("D:\\test\\19mb.pdf");
            // let source = String::from("D:\\test\\1.txt");
            let dest = String::from("D:\\test\\1enc3");
            print!("encrypting");
            encryptor.encrypt(&source, &dest);
            let decryptor = CCFileDecryptor::from(&key);
            let dec_source = String::from("D:\\test\\1enc3");
            let dec_dest = String::from("D:\\test\\dec.pdf");
            // let dec_dest = String::from("D:\\test\\1dec.txt");
            print!("decrypting");
            decryptor.decrypt(&dec_source,&dec_dest);
            print!("done")
        }
    }