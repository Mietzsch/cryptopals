use crate::{
    s03::aes_ctr::{aes128_ctr_decode, aes128_ctr_encode},
    util::generators::generate_aes_key,
};

pub struct AdminOracleCTR {
    key: Vec<u8>,
    prefix: Vec<u8>,
    postfix: Vec<u8>,
}

impl AdminOracleCTR {
    pub fn new(key: &[u8], prefix: &[u8], postfix: &[u8]) -> AdminOracleCTR {
        AdminOracleCTR {
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
        (iv.clone(), aes128_ctr_encode(&plain, &self.key, &iv))
    }

    pub fn is_admin(&self, iv: &[u8], cipher: &[u8]) -> bool {
        let plain = aes128_ctr_decode(cipher, &self.key, iv);
        for substring in plain.split(|byte| *byte == b';') {
            if substring == b"admin=true" {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn s04e02() {
        let prefix = b"comment1=cooking MCs;userdata=";
        let postfix = b";comment2= like a pound of bacon";

        let admin_oracle = AdminOracleCTR::new(&generate_aes_key(), prefix, postfix);

        let mut admin = b";admin=true".to_vec();
        let semi_position = 0;
        let equal_position = 6;
        admin[semi_position] ^= b';';
        admin[equal_position] ^= b'=';

        let mut encr = admin_oracle.encrypt(&admin);

        encr.1[prefix.len() + semi_position] ^= b';';
        encr.1[prefix.len() + equal_position] ^= b'=';

        let success = admin_oracle.is_admin(&encr.0, &encr.1);

        assert!(success);
    }
}
