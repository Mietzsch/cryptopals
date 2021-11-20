use std::fs;

use cryptopals::{s02::aes_cbc::aes128_cbc_decode, util::base_64::Base64};

fn main() {
    let key = String::from("YELLOW SUBMARINE");

    let iv = [0; 16];

    let input = fs::read_to_string("data/set2/2.txt")
        .expect("Something went wrong reading the challenge file");

    let input = input.replace("\n", "");

    let input_bytes = Base64::new_from_string(&input).unwrap();

    let decoded = aes128_cbc_decode(input_bytes.to_bytes(), key.as_bytes(), &iv);

    println!("Plaintext:\n{}", std::str::from_utf8(&decoded).unwrap())
}
