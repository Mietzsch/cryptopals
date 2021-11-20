use aes::{
    cipher::generic_array::GenericArray, Aes128, Block, BlockDecrypt, BlockEncrypt, NewBlockCipher,
};

use crate::util::xor;

use super::padding::pkcs7_padding;

pub fn aes128_cbc_encode(plain: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let key_array = GenericArray::from_slice(key);
    let aes = Aes128::new(key_array);

    let mut res = Vec::<u8>::new();

    let mut xor_text = Vec::<u8>::from(iv);

    if plain.len() % 16 != 0 {
        panic!("input must be multiple of 16!");
    }

    if iv.len() % 16 != 0 {
        panic!("input must be multiple of 16!");
    }

    for chunk in plain.chunks(16) {
        let mut block = Block::clone_from_slice(&xor::xor(&pkcs7_padding(chunk, 16), &xor_text));
        aes.encrypt_block(&mut block);
        xor_text = Vec::<u8>::from(block.to_vec());
        res.append(&mut block.to_vec());
    }

    res
}

pub fn aes128_cbc_decode(cipher: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let key_array = GenericArray::from_slice(key);
    let aes = Aes128::new(key_array);

    let mut res = Vec::<u8>::new();

    let mut xor_text = Vec::<u8>::from(iv);

    if cipher.len() % 16 != 0 {
        panic!("input must be multiple of 16!");
    }

    for chunk in cipher.chunks(16) {
        let mut block = Block::clone_from_slice(chunk);
        aes.decrypt_block(&mut block);
        res.append(&mut xor::xor(&block.to_vec(), &xor_text));
        xor_text = Vec::<u8>::from(chunk);
    }

    res
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::util::base_64::Base64;

    use super::*;

    #[test]
    fn s02e02() {
        let key = String::from("YELLOW SUBMARINE");

        let iv = [0; 16];

        let input = fs::read_to_string("data/set2/2.txt")
            .expect("Something went wrong reading the challenge file");

        let input = input.replace("\n", "");

        let input_bytes = Base64::new_from_string(&input).unwrap();

        let decoded = aes128_cbc_decode(input_bytes.to_bytes(), key.as_bytes(), &iv);

        let plain = fs::read_to_string("data/set1/7_plain.txt")
            .expect("Something went wrong reading the challenge file");

        assert_eq!(plain, std::str::from_utf8(&decoded).unwrap())
    }
}
