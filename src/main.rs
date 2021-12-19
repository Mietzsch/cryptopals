use std::str::from_utf8;

use cryptopals::{
    s02::padding::remove_pkcs7_padding,
    s03::cbc_padding_oracle::{cbc_padding_attack, CBCPaddingOracle},
    util::{base_64::Base64, generators::generate_aes_key},
};

fn main() {
    let secret =
        Base64::new_from_string("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=").unwrap();
    let oracle = CBCPaddingOracle::new(&generate_aes_key(), secret.to_bytes());

    let res = cbc_padding_attack(oracle);
    let plain = remove_pkcs7_padding(&res).unwrap();
    println!("result: {}", from_utf8(&plain).unwrap());
}
