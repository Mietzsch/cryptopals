use std::str::from_utf8;

use cryptopals::{s03::aes_ctr::aes128_ctr_decode, util::base_64::Base64};

fn main() {
    let secret = Base64::new_from_string(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
    )
    .unwrap();

    let iv = vec![0; 8];

    let plain = aes128_ctr_decode(&secret.to_bytes(), "YELLOW SUBMARINE".as_bytes(), &iv);
    println!("result: {}", from_utf8(&plain).unwrap());
}
