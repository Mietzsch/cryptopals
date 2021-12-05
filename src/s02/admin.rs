use std::str::from_utf8;

use crate::{
    s01::aes_ecb::{aes128_ecb_decode, aes128_ecb_encode},
    s02::padding::pkcs7_padding,
    util::generators::generate_aes_key,
};

use super::aes_cbc::{aes128_cbc_decode, aes128_cbc_encode};

pub struct AdminOracle {
    key: Vec<u8>,
}

impl AdminOracle {
    pub fn profile_for(&self, email: &[u8]) -> Vec<u8> {
        let mut plain = Vec::new();

        plain.append(&mut "email=".as_bytes().to_vec());
        plain.append(&mut email.to_vec());
        plain.append(&mut "&uid=10&role=user".as_bytes().to_vec());
        aes128_ecb_encode(&plain, &self.key)
    }
    pub fn decrypt(&self, cipher: &[u8]) -> String {
        let mut plain = aes128_ecb_decode(cipher, &self.key);
        let last_byte = *plain.last().unwrap();
        if (1..16).contains(&last_byte) {
            plain.truncate(plain.len() - last_byte as usize);
        }
        from_utf8(&plain).unwrap().to_string()
    }
}

pub struct AdminOracleCBC {
    key: Vec<u8>,
    prefix: Vec<u8>,
    postfix: Vec<u8>,
}

impl AdminOracleCBC {
    pub fn new(key: &[u8], prefix: &[u8], postfix: &[u8]) -> AdminOracleCBC {
        AdminOracleCBC {
            key: key.to_vec(),
            prefix: prefix.to_vec(),
            postfix: postfix.to_vec(),
        }
    }

    pub fn encrypt(&self, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut plain = Vec::new();
        plain.append(&mut self.prefix.clone());
        plain.append(&mut input.to_vec());
        plain.append(&mut self.postfix.clone());

        let iv = generate_aes_key();
        (iv.clone(), aes128_cbc_encode(&plain, &self.key, &iv))
    }

    pub fn is_admin(&self, iv: &[u8], cipher: &[u8]) -> bool {
        let plain = aes128_cbc_decode(cipher, &self.key, iv);
        for substring in plain.split(|byte| *byte == b';') {
            if substring == b"admin=true" {
                return true;
            }
        }
        false
    }
}

pub fn cut_and_paste() -> String {
    let oracle = AdminOracle {
        key: generate_aes_key(),
    };

    let mut admin = pkcs7_padding("admin".as_bytes(), 16);
    let dummy_email = "1234@5.com";
    assert!(dummy_email.as_bytes().len() == 10);

    let mut fake_email = dummy_email.as_bytes().to_vec();
    fake_email.append(&mut admin);

    let dummy_profile = oracle.profile_for(&fake_email);
    let admin_cipher = &dummy_profile[16..32];

    let email = "123456@78.com";
    assert!(email.as_bytes().len() == 13);

    let mut profile = oracle.profile_for(&email.as_bytes());

    profile.splice(32.., admin_cipher.iter().cloned());

    oracle.decrypt(&profile)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn s02e05() {
        assert_eq!(cut_and_paste().contains("role=admin"), true);
    }

    #[test]
    fn s02e08() {
        let prefix = b"comment1=cooking MCs;userdata=";
        let postfix = b";comment2= like a pound of bacon";

        let admin_oracle = AdminOracleCBC::new(&generate_aes_key(), prefix, postfix);

        let pad = [0; 2];
        let zero_block = [0; 16];

        let mut admin = b"\0\0\0\0\0;admin=true".to_vec();
        let semi_position = 5;
        let equal_position = 11;
        admin[semi_position] ^= b';';
        admin[equal_position] ^= b'=';

        let mut input = Vec::new();
        input.append(&mut pad.to_vec());
        input.append(&mut zero_block.to_vec());
        input.append(&mut admin);

        let mut encr = admin_oracle.encrypt(&input);

        encr.1[prefix.len() + pad.len() + semi_position] ^= b';';
        encr.1[prefix.len() + pad.len() + equal_position] ^= b'=';

        let success = admin_oracle.is_admin(&encr.0, &encr.1);

        assert!(success);
    }
}
