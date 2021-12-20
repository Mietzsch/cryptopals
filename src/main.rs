use std::fs;
use std::str::from_utf8;

use cryptopals::s01::key_xor_analyzer::KeyXorAnalyzer;
use cryptopals::s03::aes_ctr_fixed_nonce::attack_fixed_none;

fn main() {
    println!("preparing map");
    let testdata = fs::read_to_string("data/Shakespeare.txt")
        .expect("Something went wrong reading the shakespeare file");
    let testdata = testdata.replace('\n', "");

    let analyzer = KeyXorAnalyzer::new(&testdata.as_bytes());
    println!("Finished reading map");

    let input = fs::read_to_string("data/set3/4_cipher.txt")
        .expect("Something went wrong reading the challenge file");

    let mut input_vec = Vec::<Vec<u8>>::new();
    for line in input.lines() {
        let secret = hex::decode(line).unwrap();
        input_vec.push(secret);
    }

    let decoded_vec = attack_fixed_none(input_vec, &analyzer);

    for decoded in decoded_vec {
        println!(
            "Plaintext: {}",
            from_utf8(&decoded).unwrap_or_else(|_| "NOT UTF8")
        );
    }
}
