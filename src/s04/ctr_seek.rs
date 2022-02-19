use crate::s03::aes_ctr::{
    aes128_ctr_decode_with_full_iv, aes128_ctr_encode_with_full_iv, increment_iv,
};

pub fn edit(cipher: &[u8], key: &[u8], iv: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
    let block_offset = (offset / 16) * 16;
    let new_len = newtext.len();
    let mut res = cipher.to_vec();

    let iv_len = iv.len();

    let mut iv: Vec<u8> = iv.to_vec();
    let mut append_zero = vec![0; 16 - iv_len];
    iv.append(&mut append_zero);

    for _ in 0..block_offset {
        increment_iv(&mut iv, iv_len);
    }

    let offset_pos = offset % 16;
    let offset_end = block_offset + offset_pos + new_len;
    let mut decrypted =
        aes128_ctr_decode_with_full_iv(&cipher[block_offset..offset_end], key, &iv, iv_len);

    decrypted.splice(offset_pos..offset_pos + new_len, newtext.to_vec());
    let encrypted = aes128_ctr_encode_with_full_iv(&decrypted, key, &iv, iv_len);
    res.splice(block_offset..offset_end, encrypted);
    res
}

#[cfg(test)]
mod tests {

    use std::fs;

    use crate::{
        s03::aes_ctr::{aes128_ctr_decode, aes128_ctr_encode},
        util::xor::xor,
    };

    use super::*;

    #[test]
    fn s04e01_functional() {
        let iv = vec![0; 8];

        let key = "YELLOW SUBMARINE".as_bytes();

        let plain = fs::read_to_string("data/set1/7_plain.txt")
            .expect("Something went wrong reading the challenge file");

        let cipher = aes128_ctr_encode(plain.as_bytes(), key, &iv);

        let modified_encrypted = edit(&cipher, key, &iv, 5, "AAAAAA".as_bytes());

        let decrypted = aes128_ctr_decode(&modified_encrypted, key, &iv);

        let mut plain_bytes = plain.as_bytes().to_vec();

        plain_bytes.splice(5..11, "AAAAAA".as_bytes().to_vec());

        assert_eq!(decrypted, plain_bytes);
    }

    #[test]
    fn s04e01_attack() {
        let iv = vec![0; 8];

        let key = "YELLOW SUBMARINE".as_bytes();

        let plain = fs::read_to_string("data/set1/7_plain.txt")
            .expect("Something went wrong reading the challenge file");

        let cipher = aes128_ctr_encode(plain.as_bytes(), key, &iv);

        let null_cipher = edit(&cipher, key, &iv, 0, &vec![0; cipher.len()]);

        let new_plain = xor(&cipher, &null_cipher);

        assert_eq!(plain.as_bytes(), &new_plain);
    }
}
