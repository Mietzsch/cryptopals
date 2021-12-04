use std::{fs, str::from_utf8};

use cryptopals::{
    s02::ecb_decryption::{decrypt_ecb, ECBOracleHard},
    util::{base_64::Base64, generators::generate_aes_key},
};
use rand::{Rng, RngCore};

fn main() {
    let input = fs::read_to_string("data/set2/4.txt")
        .expect("Something went wrong reading the challenge file");
    let input = input.replace("\n", "");

    let random_vec_len = rand::thread_rng().gen_range(0..32);
    let mut random_vec = vec![0; random_vec_len];
    rand::thread_rng().fill_bytes(&mut random_vec);

    let oracle = ECBOracleHard::new(
        Base64::new_from_string(&input).unwrap().to_bytes(),
        &generate_aes_key(),
        &random_vec,
    );

    let dec = decrypt_ecb(&oracle);

    let dec_str = from_utf8(&dec).unwrap();

    println!("Decoded:\n{}", dec_str);
}
