
use std::{
    fs::File,
    io::{BufWriter, Write},
};

pub struct FileWriter {
    buf_writer: BufWriter<File>,
}

impl FileWriter {
    pub fn from(file_path: &str) -> Self {
        let file = File::options()
            .create(true)
            .write(true)
            .open(file_path)
            .unwrap();
        let buf_writer = BufWriter::new(file);
        FileWriter { buf_writer }
    }

    pub fn write(&mut self, data: Vec<u8>) {
        match self.buf_writer.write(&data) {
            Ok(_) => (),
            Err(_) => panic!("Failed to write bytes"),
        }
    }

    pub fn close(&mut self) {
        self.buf_writer.flush().unwrap()
    }
}

pub struct ChunkWriter {
    buf_writer: BufWriter<File>,
}

impl ChunkWriter {
    pub fn from(file_path: &str) -> Self {
        let file = File::options()
            .create(true)
            .write(true)
            .open(file_path)
            .unwrap();
        let buf_writer = BufWriter::new(file);
        ChunkWriter { buf_writer }
    }

    pub fn write(&mut self, data: Vec<u8>) {
        let length = data.len();
        let len32: u32 = length.try_into().unwrap();
        let length_bytes = len32.to_be_bytes();
        self.write_internal(length_bytes.to_vec());
        self.write_internal(data);
    }

    fn write_internal(&mut self, data: Vec<u8>) {
        match self.buf_writer.write(&data) {
            Ok(_) => (),
            Err(_) => panic!("Failed to write bytes"),
        }
    }

    pub fn close(&mut self) {
        self.buf_writer.flush().unwrap()
    }
}
