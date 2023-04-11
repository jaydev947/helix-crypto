pub mod readers {

    use std::{
        fs::File,
        io::{BufRead, BufReader, Read},
    };

    

    pub struct FileReader {
        buf_reader: BufReader<File>,
        has_more: bool,
    }

    impl FileReader {
        pub fn from(capacity: u32, file_path: String) -> Self {
            let file = File::open(file_path).unwrap();
            let cap = capacity.try_into().unwrap();
            let buf_reader = BufReader::with_capacity(cap, file);
            FileReader {
                buf_reader,
                has_more: true,
            }
        }

        pub fn next(&mut self) -> Option<Vec<u8>> {
            let reader = &mut self.buf_reader;
            if !self.has_more {
                return Option::None;
            }
            let (buf, len) = {
                let buf = reader.fill_buf().unwrap().to_vec();
                let len = buf.len();
                (buf, len)
            };
            if len > 0 {
                reader.consume(len);
                return Option::Some(buf);
            }
            self.has_more = false;
            Option::None
        }
    }

    pub struct ChunkReader {
        file: File,
        has_more: bool,
    }

    impl ChunkReader {
        pub fn from(file_path: String) -> Self {
            let file = File::open(file_path).unwrap();
            ChunkReader {
                file,
                has_more: true,
            }
        }

        pub fn next(&mut self) -> Option<Vec<u8>> {
            if !self.has_more {
                return Option::None;
            }
            let mut length_bytes = [0; 4];
            let count = self.file.read(&mut length_bytes).unwrap();
            if count == 0 {
                self.has_more = false;
                return Option::None;
            }
            let length: u32 = u32::from_be_bytes(length_bytes);
            let mut buffer = Self::new_buffer(length);
            self.file.read_exact(&mut buffer).unwrap();
            return Option::Some(buffer);
        }

        fn new_buffer(length: u32) -> Vec<u8>{
            let size = length.try_into().unwrap();
            let mut buffer = Vec::with_capacity(size);
            for _ in 0..length{
                buffer.push(0);
            }
            buffer
        }

    }
}

pub mod writer {

    use std::{
        fs::File,
        io::{BufWriter, Write},
    };

    pub struct FileWriter {
        buf_writer: BufWriter<File>,
    }

    impl FileWriter {
        pub fn from(file_path: String) -> Self {
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
        pub fn from(file_path: String) -> Self {
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
            let len32:u32 = length.try_into().unwrap();
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
}
