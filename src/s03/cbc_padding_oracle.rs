use indicatif::ProgressIterator;

use crate::{
    s02::{
        aes_cbc::{aes128_cbc_decode, aes128_cbc_encode},
        padding::remove_pkcs7_padding,
    },
    util::{generators::generate_aes_key, progress_bar::create_progress_bar, xor::xor},
};

pub struct CBCPaddingOracle {
    key: Vec<u8>,
    plain: Vec<u8>,
}

impl CBCPaddingOracle {
    pub fn new(key: &[u8], plain: &[u8]) -> CBCPaddingOracle {
        CBCPaddingOracle {
            key: key.to_vec(),
            plain: plain.to_vec(),
        }
    }
    pub fn encrypt(&self) -> (Vec<u8>, Vec<u8>) {
        let iv = generate_aes_key();
        (iv.clone(), aes128_cbc_encode(&self.plain, &self.key, &iv))
    }

    pub fn has_valid_padding(&self, iv: &[u8], cipher: &[u8]) -> bool {
        let plain = aes128_cbc_decode(cipher, &self.key, iv);
        let padding_result = remove_pkcs7_padding(&plain);
        padding_result.is_ok()
    }
}

pub fn cbc_padding_attack(oracle: CBCPaddingOracle) -> Vec<u8> {
    let ciphertext = oracle.encrypt();
    let blocks = ciphertext.1.len() / 16;
    let mut result = Vec::new();

    for offset in (0..blocks).progress_with(create_progress_bar(blocks as u64)) {
        if offset == 0 {
            result.append(&mut cbc_padding_attack_blocks(
                &oracle,
                &ciphertext.0,
                &ciphertext.1[offset * 16..(offset + 1) * 16],
            ));
        } else {
            result.append(&mut cbc_padding_attack_blocks(
                &oracle,
                &ciphertext.1[(offset - 1) * 16..offset * 16],
                &ciphertext.1[offset * 16..(offset + 1) * 16],
            ));
        }
    }

    result
}

fn cbc_padding_attack_blocks(
    oracle: &CBCPaddingOracle,
    previous: &[u8],
    current: &[u8],
) -> Vec<u8> {
    let mut zeroizing_iv = [0; 16];

    for byte_number in (0..16).rev() {
        let mut iv_for_this_byte = zeroizing_iv;
        for item in iv_for_this_byte.iter_mut().skip(byte_number + 1) {
            *item ^= (16 - byte_number) as u8;
        }
        for i in 0..=255 {
            let mut iv = iv_for_this_byte;
            iv[byte_number] ^= i;
            if oracle.has_valid_padding(&iv, current) {
                if byte_number > 0 {
                    iv[byte_number - 1] ^= 128;
                    if oracle.has_valid_padding(&iv, current) {
                        let plain_byte = i ^ (16 - byte_number as u8);
                        zeroizing_iv[byte_number] = plain_byte;
                        continue;
                    }
                } else {
                    let plain_byte = i ^ (16 - byte_number as u8);
                    zeroizing_iv[byte_number] = plain_byte;
                    continue;
                }
            }
        }
    }
    xor(&zeroizing_iv, previous)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::util::base_64::Base64;

    use super::*;

    #[test]
    fn s03e01() {
        let input = fs::read_to_string("data/set3/1.txt")
            .expect("Something went wrong reading the challenge file");
        let output = fs::read_to_string("data/set3/1_plain.txt")
            .expect("Something went wrong reading the challenge file");
        for i in 0..10 {
            let secret = Base64::new_from_string(input.lines().nth(i).unwrap()).unwrap();
            let oracle = CBCPaddingOracle::new(&generate_aes_key(), secret.to_bytes());
            let res = cbc_padding_attack(oracle);
            let plain = remove_pkcs7_padding(&res).unwrap();
            assert_eq!(output.lines().nth(i).unwrap().as_bytes(), plain)
        }
    }
}
