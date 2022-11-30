use std::io::{Error, ErrorKind, Read, Write};

// The first few digits of pi but in hex (314159...)
pub static INTEGRITY_BLOCK: u128 = 0x6063CB8EB347CEC6B827FBF1B4197A7C;

pub type PasswordProducer = fn() -> String;

#[derive(Debug)]
pub enum SfsErrorKind{
    CorruptedFile,
    IoError,
    CantWrite,
    CantOpenFile,
    NotPresent,
    AlreadyPresent,
    BadUsage,
    IncorrectPassword
}

pub trait ReadBlock{
    fn read_block(&mut self) -> Result<Result<u128, (u128, usize)>, SfsErrorKind>;
    fn read_block_exact(&mut self) -> Result<u128, SfsErrorKind>{
        match self.read_block()?{
            Ok(block) => Ok(block),
            Err(_) => {
                Err(SfsErrorKind::CorruptedFile)
            },
        }
    }
}

pub trait WriteBlock{
    fn write_block(&mut self, block: u128) -> Result<(), SfsErrorKind>;
}

impl<T: Write> WriteBlock for T{
    fn write_block(&mut self, block: u128) -> Result<(), SfsErrorKind>{
        match self.write(&block.to_le_bytes()){
            Ok(16) => Ok(()),
            Ok(_) => Err(SfsErrorKind::CantWrite),
            Err(e) => Err(SfsErrorKind::IoError)
        }
    }
}

impl<T: Read> ReadBlock for T{
    fn read_block(&mut self) -> Result<Result<u128, (u128, usize)>, SfsErrorKind>{
        let mut block = [0; 16];
        match self.read(&mut block){
            Ok(16) => Ok(Ok(u128::from_le_bytes(block))),
            Ok(len) => Ok(Err((u128::from_le_bytes(block), len))),
            Err(e) => Err(SfsErrorKind::IoError)
        }
    }
}
