use super::mt_rng::MTRng;

use crate::util::{progress_bar::create_progress_bar, xor};

pub fn mt_rng_ctr_encode(plain: &[u8], key: u16) -> Vec<u8> {
    mt_rng_ctr_xor(plain, key)
}

pub fn mt_rng_ctr_decode(plain: &[u8], key: u16) -> Vec<u8> {
    mt_rng_ctr_xor(plain, key)
}

fn mt_rng_ctr_xor(input: &[u8], key: u16) -> Vec<u8> {
    let mut rng = MTRng::new(key.into());
    let mut res = Vec::<u8>::new();

    for chunk in input.chunks(4) {
        let current_u32 = rng.extract_number();
        let keystream = [
            ((current_u32 & 0xFF000000) >> 24) as u8,
            ((current_u32 & 0x00FF0000) >> 16) as u8,
            ((current_u32 & 0x0000FF00) >> 08) as u8,
            ((current_u32 & 0x000000FF) >> 00) as u8,
        ];
        res.append(&mut xor::xor(chunk, &keystream));
    }
    res
}

pub fn crack_seed(known_plaintext: &[u8], ciphertext: &[u8]) -> Option<u16> {
    let plaintext_offset = ciphertext.len() - known_plaintext.len();
    let mut test_plain = vec![0; plaintext_offset];
    test_plain.append(&mut known_plaintext.to_vec());

    let progress_bar = create_progress_bar(u16::MAX as u64);
    for key in 0..=u16::MAX {
        let new_ciper = mt_rng_ctr_encode(&test_plain, key);
        if &new_ciper[plaintext_offset..] == &ciphertext[plaintext_offset..] {
            return Some(key);
        }
        if key % 256 == 0 {
            progress_bar.inc(256);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::str::from_utf8;

    use rand::{Rng, RngCore};

    use super::*;

    #[test]
    fn test_mt_stream_cipher() {
        let plaintext = "SECRET_TEXT";
        let key = 4389;
        let ciphertext = mt_rng_ctr_encode(plaintext.as_bytes(), key);
        let dec = mt_rng_ctr_decode(&ciphertext, key);
        assert_eq!(plaintext, from_utf8(&dec).unwrap());
    }

    #[test]
    fn s03e08_seed() {
        let known_plaintext = b"AAAAAAAAAAAAA";
        let random_vec_len = rand::thread_rng().gen_range(0..32);
        let mut random_vec = vec![0; random_vec_len];
        rand::thread_rng().fill_bytes(&mut random_vec);
        random_vec.append(&mut known_plaintext.to_vec());
        let key = rand::thread_rng().gen();

        let ciphertext = mt_rng_ctr_encode(&random_vec, key);
        let key_guess = crack_seed(known_plaintext, &ciphertext).unwrap();
        assert_eq!(key, key_guess);
    }
}
