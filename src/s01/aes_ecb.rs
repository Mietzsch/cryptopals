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

    for i in 0..blocks {
        let mut block = Block::clone_from_slice(&plain[16 * i..16 * (i + 1)]);
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

    for i in 0..blocks {
        let mut block = Block::clone_from_slice(&cipher[16 * i..16 * (i + 1)]);
        aes.decrypt_block(&mut block);
        res.append(&mut block.to_vec());
    }

    res
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
            .expect("Something went wrong reading the challenge file");

        assert_eq!(str::from_utf8(&decode).unwrap(), plain);
    }
}
