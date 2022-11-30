use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Seek, SeekFrom, Write};
use crate::cipher::Cipher;
use crate::types::{INTEGRITY_BLOCK, PasswordProducer, ReadBlock, SfsErrorKind, WriteBlock};

// A file created with this application
pub struct SfsFile {
    file: std::fs::File,
    cipher: Cipher
}

impl SfsFile {
    pub fn open_or_create(path: &str, password: PasswordProducer) -> Result<Self, SfsErrorKind>{
        match Self::open(path, password){
            Ok(result) => Ok(result),
            Err(SfsErrorKind::CantOpenFile) => Self::create(path, password),
            Err(e) => Err(e)
        }
    }

    pub fn create(path: &str, password: PasswordProducer) -> Result<Self, SfsErrorKind> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(true)
            .open(path)
            .map_err(|_| SfsErrorKind::CantOpenFile)?;
        let (cipher, salt) = Cipher::new(password);
        let integrity = cipher.encrypt(INTEGRITY_BLOCK);
        file.write_block(salt)?;
        file.write_block(integrity)?;
        Ok(Self { file, cipher })
    }

    pub fn open(path: &str, password: PasswordProducer) -> Result<Self, SfsErrorKind> {
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(path)
            .map_err(|_| SfsErrorKind::CantOpenFile)?;
        let salt = file.read_block_exact()?;
        let integrity = file.read_block_exact()?;
        let cipher = Cipher::with_salt(salt, password);
        if cipher.decrypt(integrity) != INTEGRITY_BLOCK {
            return Err(SfsErrorKind::IncorrectPassword);
        }
        Ok(Self { file, cipher })
    }

    fn read_head(&mut self, loc: usize) -> Result<usize, SfsErrorKind>{
        self.file.seek(SeekFrom::Start((loc * 16) as u64));
        let length = self.file
            .read_block_exact()?;
        Ok(self.cipher.decrypt(length) as usize)
    }

    fn num_blocks(&mut self)-> Result<usize, SfsErrorKind>{
        let size = self.file
            .seek(SeekFrom::End(0))
            .map_err(|e| SfsErrorKind::IoError)?;
        if size%16 != 0 {
            Err(SfsErrorKind::CorruptedFile)
        }else{
            Ok((size/ 16) as usize)
        }
    }

    fn read_data(&mut self, dest: &mut impl Write, loc: usize) -> Result<usize, SfsErrorKind>{
        let length = self.read_head(loc)?;
        // TODO Should actually be some IV.
        let mut prev_block = 0;
        let mut integrity = 0;
        for _ in 0..(length/16){
            let block = self.file.read_block_exact()?;
            let block = self.cipher.decrypt(block) ^ prev_block;
            integrity ^= block;
            prev_block = self.cipher.encrypt(block ^ prev_block);
            dest.write(&block.to_le_bytes())
                .map_err(|e| SfsErrorKind::IoError);
        }
        let remainder = length % 16;
        if remainder > 0{
            let block = self.file.read_block_exact()?;
            let block = self.cipher.decrypt(block) ^ prev_block;
            integrity ^= block;
            prev_block = self.cipher.encrypt(block ^ prev_block);
            let written = dest
                .write(&block.to_le_bytes()[0..remainder])
                .map_err(|_|SfsErrorKind::IoError)?;
            if written != remainder{
                return Err(SfsErrorKind::IoError);
            }
        }
        let integrity_check = self.file.read_block_exact()?;
        let integrity_check = self.cipher.decrypt(integrity_check);
        if integrity != integrity_check{
            return Err(SfsErrorKind::CorruptedFile);
        }
        Ok(loc + 2 + (length + 15)/16)
    }

    fn write_data(&mut self, data: &mut impl ReadBlock) -> Result<(), SfsErrorKind>{
        // TODO Should actually be some IV.
        let mut prev_block = 0;
        let mut length = 0usize;
        let start = self.file
            .seek(SeekFrom::End(16))
            .map_err(|_|SfsErrorKind::IoError)? - 16;
        if start % 16 != 0{
            return Err(SfsErrorKind::CorruptedFile)
        }
        let mut integrity = 0;
        loop{
            match data.read_block()?{
                Ok(block) => {
                    length += 16;
                    prev_block = self.cipher.encrypt(block ^ prev_block);
                    integrity ^= block;
                    self.file.write_block(prev_block)?;
                }
                Err((block, len)) => {
                    prev_block = self.cipher.encrypt(block ^ prev_block);
                    integrity ^= block;
                    self.file.write_block(prev_block)?;
                    length += len;
                    break;
                }
            }
        }
        integrity = self.cipher.encrypt(integrity);
        self.file.write_block(integrity)?;
        self.file
            .seek(SeekFrom::Start(start))
            .map_err(|_|SfsErrorKind::IoError)?;
        let block = self.cipher.encrypt(length as u128);
        self.file.write_block(block)
    }

    fn find(&mut self, id: &str) -> Result<Option<usize>, SfsErrorKind>{
        let num_blocks = self.num_blocks()?;
        let id = id.as_bytes();
        let mut buffer = Vec::<u8>::new();
        let mut loc = 2;
        while loc < num_blocks{
            loc = self.read_data(&mut buffer, loc)?;
            if buffer.as_slice().eq(id){
                return Ok(Some(loc))
            }
            buffer.clear();
            loc += 2 + (self.read_head(loc)? + 15)/16;
        }
        Ok(None)
    }

    pub fn write(&mut self, mut id: &str, mut data: impl ReadBlock) -> Result<(), SfsErrorKind>{
        if let Some(loc) = self.find(id)?{
            Err(SfsErrorKind::AlreadyPresent)
        }else{
            self.write_data(&mut id.as_bytes())?;
            self.write_data(&mut data)
        }
    }

    pub fn read(&mut self, id: &str, mut dest: impl Write) -> Result<(), SfsErrorKind>{
        if let Some(loc) = self.find(id)?{
            self.read_data(&mut dest, loc)?;
            Ok(())
        }else{
            Err(SfsErrorKind::NotPresent)
        }
    }

    pub fn list(&mut self, mut dest: impl Write) -> Result<(), SfsErrorKind>{
        let num_blocks = self.num_blocks()?;
        let mut loc = 2;

        while loc + 1 < num_blocks {
            loc = self.read_data(&mut dest, loc).unwrap();
            loc += 2 + (self.read_head(loc).unwrap() + 15)/16;
            dest.write(b"\n")
                .map_err(|e| SfsErrorKind::IoError);
        }
        Ok(())
    }
}