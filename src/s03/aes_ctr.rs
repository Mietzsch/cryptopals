use aes::{cipher::generic_array::GenericArray, Aes128, Block, BlockEncrypt, NewBlockCipher};

use crate::util::xor;

pub fn aes128_ctr_encode(plain: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    aes128_ctr_xor(plain, key, iv)
}

pub fn aes128_ctr_encode_with_full_iv(
    plain: &[u8],
    key: &[u8],
    iv: &[u8],
    iv_len: usize,
) -> Vec<u8> {
    aes128_ctr_xor_with_full_iv(plain, key, iv, iv_len)
}

pub fn aes128_ctr_decode(cipher: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    aes128_ctr_xor(cipher, key, iv)
}

pub fn aes128_ctr_decode_with_full_iv(
    cipher: &[u8],
    key: &[u8],
    iv: &[u8],
    iv_len: usize,
) -> Vec<u8> {
    aes128_ctr_xor_with_full_iv(cipher, key, iv, iv_len)
}

fn aes128_ctr_xor(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let iv_len = iv.len();

    let mut iv: Vec<u8> = iv.to_vec();
    let mut append_zero = vec![0; 16 - iv_len];
    iv.append(&mut append_zero);

    aes128_ctr_xor_with_full_iv(input, key, &iv, iv_len)
}

fn aes128_ctr_xor_with_full_iv(input: &[u8], key: &[u8], iv: &[u8], iv_len: usize) -> Vec<u8> {
    if iv.len() != 16 {
        panic!("IV has to be 16 Bytes long!");
    }
    let key_array = GenericArray::from_slice(key);
    let aes = Aes128::new(key_array);
    let mut res = Vec::<u8>::new();

    let mut iv: Vec<u8> = iv.to_vec();

    for chunk in input.chunks(16) {
        let mut block = Block::clone_from_slice(&iv);
        aes.encrypt_block(&mut block);
        res.append(&mut xor::xor(chunk, &block));
        increment_iv(&mut iv, iv_len);
    }
    res
}

pub fn increment_iv(iv: &mut Vec<u8>, original_len: usize) {
    let mut overflow = true;
    let mut i = original_len;
    while overflow && i < iv.len() {
        if iv[i] == 255 {
            iv[i] = 0;
            i += 1;
        } else {
            iv[i] += 1;
            overflow = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::from_utf8;

    use crate::util::base_64::Base64;

    use super::*;

    #[test]
    fn s03e02() {
        let secret = Base64::new_from_string(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
        )
        .unwrap();

        let iv = vec![0; 8];

        let key = "YELLOW SUBMARINE";

        let dec = aes128_ctr_decode(&secret.to_bytes(), key.as_bytes(), &iv);

        let plain = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";
        assert_eq!(plain, from_utf8(&dec).unwrap());

        let enc = aes128_ctr_encode(plain.as_bytes(), key.as_bytes(), &iv);

        assert_eq!(secret.to_bytes(), enc);
    }
}
