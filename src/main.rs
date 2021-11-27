use std::{fs, str::from_utf8};

use cryptopals::{s02::ecb_decryption::decrypt_ecb_simple, util::base_64::Base64};

fn main() {
    let input = fs::read_to_string("data/set2/4.txt")
        .expect("Something went wrong reading the challenge file");
    let input = input.replace("\n", "");

    let dec = decrypt_ecb_simple(Base64::new_from_string(&input).unwrap().to_bytes());

    let dec_str = from_utf8(&dec).unwrap();

    print!("Decoded string:\n{}", dec_str);
}
