use rand::Rng;

use crate::{
    s01::aes_ecb::{aes128_ecb_encode, aes_ecb_detector},
    util::generators::generate_aes_key,
};

use super::aes_cbc::aes128_cbc_encode;

pub fn encryption_oracle(input: &[u8]) -> (Vec<u8>, bool) {
    let aes_key = generate_aes_key();
    let mut rng = rand::thread_rng();
    let prepend_size: usize = rng.gen_range(5..10);
    let append_size: usize = rng.gen_range(5..10);

    let mut plain = Vec::<u8>::new();

    for _ in 0..prepend_size {
        plain.push(rng.gen());
    }

    plain.append(&mut input.to_vec());

    for _ in 0..append_size {
        plain.push(rng.gen());
    }

    let choice: bool = rng.gen();
    if choice {
        (aes128_ecb_encode(&plain, &aes_key), choice)
    } else {
        (
            aes128_cbc_encode(&plain, &aes_key, &generate_aes_key()),
            choice,
        )
    }
}

pub fn detect_ecb_cbc() -> (bool, bool) {
    let plain = [0; 160];

    let result = encryption_oracle(&plain);
    let count = aes_ecb_detector(&result.0);

    if count >= 5 {
        (true, result.1)
    } else {
        (false, result.1)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn s02e03() {
        for _ in 0..10 {
            let result = detect_ecb_cbc();
            assert_eq!(result.0, result.1);
        }
    }
}
