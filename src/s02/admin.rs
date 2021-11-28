use std::str::from_utf8;

use crate::{
    s01::aes_ecb::{aes128_ecb_decode, aes128_ecb_encode},
    s02::padding::pkcs7_padding,
    util::generators::generate_aes_key,
};

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
}
