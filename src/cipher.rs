use aes::Aes192;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use zeroize::Zeroize;
use crate::types::PasswordProducer;

pub struct Cipher(aes::Aes192);

impl Cipher{
    pub fn encrypt(&self, data: u128) -> u128{
        let mut bytes = data.to_le_bytes();
        self.0.encrypt_block(bytes.as_mut().into());
        return u128::from_le_bytes(bytes);
    }

    pub fn decrypt(&self, data: u128) -> u128{
        let mut bytes = data.to_le_bytes();
        self.0.decrypt_block(bytes.as_mut().into());
        return u128::from_le_bytes(bytes);
    }

    pub fn new(password: PasswordProducer) -> (Self, u128){
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt);
        let aes = Self::make_aes(salt, 13, password);
        (Self(aes), u128::from_le_bytes(salt))
    }

    pub fn with_salt(salt: u128, password: PasswordProducer) -> Self{
        Self(Self::make_aes(salt.to_le_bytes(), 13, password))
    }


    fn make_aes(salt: [u8; 16], cost: u32, password: PasswordProducer) -> Aes192{
        // Generate a password using the producer function.
        let mut password = password();

        // Copy into a vec of bytes with a null terminator.
        let mut bytes = vec![0; password.len() + 1];
        bytes[0..password.len()].copy_from_slice(password.as_bytes());

        //Clear the bytes of the original password from memory
        password.zeroize();
        drop(password);

        // Encrypt the password using the salt and cost factor
        let result = bcrypt::bcrypt(cost, salt, &*bytes);

        // Clear the null-terminated bytes from memory
        bytes.zeroize();
        drop(bytes);

        // Return the result
        Aes192::new_from_slice(&result).unwrap()
    }
}