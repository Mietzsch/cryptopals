use std::{collections::HashMap, convert::TryInto};

use aes::{
    cipher::generic_array::GenericArray, Aes128, Block, BlockDecrypt, BlockEncrypt, NewBlockCipher,
};

pub fn aes128_ecb_encode(plain: &[u8], key: &[u8]) -> Vec<u8> {
    let key_array = GenericArray::from_slice(key);
    let aes = Aes128::new(key_array);

    let mut res = Vec::<u8>::new();

    let blocks = plain.len() / 16;
    if blocks * 16 != plain.len() {
        panic!("input must be a multiple of 16!");
    }

    for chunk in plain.chunks(16) {
        let mut block = Block::clone_from_slice(chunk);
        aes.encrypt_block(&mut block);
        res.append(&mut block.to_vec());
    }

    res
}

pub fn aes128_ecb_decode(cipher: &[u8], key: &[u8]) -> Vec<u8> {
    let key_array = GenericArray::from_slice(key);
    let aes = Aes128::new(key_array);

    let mut res = Vec::<u8>::new();

    let blocks = cipher.len() / 16;

    if blocks * 16 != cipher.len() {
        panic!("input must be a multiple of 16!");
    }

    for chunk in cipher.chunks(16) {
        let mut block = Block::clone_from_slice(chunk);
        aes.decrypt_block(&mut block);
        res.append(&mut block.to_vec());
    }

    res
}

pub fn aes_ecb_detector(cipher: &[u8]) -> usize {
    let mut map: HashMap<[u8; 16], usize> = HashMap::new();

    let blocks = cipher.len() / 16;

    if blocks * 16 != cipher.len() {
        panic!("input must be a multiple of 16!");
    }

    for chunk in cipher.chunks(16) {
        let value = map
            .entry(chunk.try_into().expect("input must be a multiple of 16!"))
            .or_insert(0);
        *value += 1;
    }

    let expected_count = (blocks as f64 / f64::powi(2.0, 128)).ceil() as usize;

    map.values().max().unwrap_or(&0) - expected_count
}

#[cfg(test)]
mod tests {

    use crate::util::base_64::Base64;

    use super::*;

    #[test]
    fn s01e07() {
        use std::{fs, str};

        let input = fs::read_to_string("data/set1/7.txt")
            .expect("Something went wrong reading the challenge file");

        let input = input.replace("\n", "");

        let input_bytes = Base64::new_from_string(&input).unwrap();

        let key = String::from("YELLOW SUBMARINE");

        let decode = aes128_ecb_decode(input_bytes.to_bytes(), key.as_bytes());

        let plain = fs::read_to_string("data/set1/7_plain.txt")
            .expect("Something went wrong reading the plain file");

        assert_eq!(str::from_utf8(&decode).unwrap(), plain);
    }

    #[test]
    fn s01e08() {
        use std::fs;

        let input = fs::read_to_string("data/set1/8.txt")
            .expect("Something went wrong reading the challenge file");

        let reducer = |previous: (usize, usize), str: (usize, &str)| -> (usize, usize) {
            let bytes = hex::decode(str.1).expect("decoding failed");
            let res = aes_ecb_detector(&bytes);
            if previous.0 < res {
                println!("New best: {} in line {}, was {}", res, str.0, previous.0);
                (res, str.0)
            } else {
                previous
            }
        };

        let res: (usize, usize) = input.lines().enumerate().fold((0, 0), reducer);
        assert_eq!(res.1, 132);
    }
}
