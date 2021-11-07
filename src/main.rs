use cryptopals::{s01::aes_ecb::aes128_ecb_decode, util::base_64::Base64};

fn main() {
    use std::{fs, str};

    let input = fs::read_to_string("data/set1/7.txt")
        .expect("Something went wrong reading the challenge file");

    let input = input.replace("\n", "");

    let input_bytes = Base64::new_from_string(&input).unwrap();

    let key = String::from("YELLOW SUBMARINE");

    let decode = aes128_ecb_decode(input_bytes.to_bytes(), key.as_bytes());

    println!("decoded text:\n{}", str::from_utf8(&decode).unwrap());
}
