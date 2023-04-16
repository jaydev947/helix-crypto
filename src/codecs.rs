pub mod hex {
    pub fn decode(data: String,out: &mut [u8]) {
        hex::decode_to_slice(data, out).unwrap();
    }

    pub fn decode_vec(data: String)->Vec<u8>{
        hex::decode(data).unwrap()
    }

    pub fn encode(data: &[u8]) -> String {
        hex::encode(data)
    }

    pub fn encode_vec(data: Vec<u8>) -> String {
        hex::encode(data)
    }


}
