pub(crate) mod hex {
    pub fn decode(data: String, out: &mut [u8]) {
        hex::decode_to_slice(data, out).unwrap();
    }

    pub fn decode_vec(data: &str) -> Vec<u8> {
        hex::decode(data).unwrap()
    }

    pub fn encode(data: &[u8]) -> String {
        hex::encode(data)
    }

    pub fn encode_vec(data: Vec<u8>) -> String {
        hex::encode(data)
    }
}

pub(crate) mod uuid {
    use bson::oid::ObjectId;

    pub fn generate() -> String {
        ObjectId::new().to_hex()
    }
}

pub(crate) mod hash {

    use sha2::{Sha256, Digest};
use std::{io, fs};

    pub fn hash_file(path: &str) -> String {
        let mut hasher = Sha256::new();
        let mut file = fs::File::open(path).unwrap();
        io::copy(&mut file, &mut hasher).unwrap();
        let hash_bytes = hasher.finalize();
        hex::encode(hash_bytes)
    }

    pub fn hash_string(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let hash_bytes = hasher.finalize();
        hex::encode(hash_bytes)
    }

    
}

#[cfg(test)]
    mod tests {
        use super::hash::hash_file;

        
    
        #[test]
        fn file_encrypt_decrypt_test() {
           
            let source = String::from("D:\\Other\\Badhaai Do (2022) [1080p] [WEBRip] [5.1] [YTS.MX]\\Badhaai.Do.2022.1080p.WEBRip.x264.AAC5.1-[YTS.MX].mp4");
            // let source = String::from("D:\\test\\19mb.pdf");
            let hash = hash_file(&source);
            println!("{}",hash)
        }
    }
