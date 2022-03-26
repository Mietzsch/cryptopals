use std::convert::TryInto;

use num_bigint::BigUint;

use crate::{
    s02::{
        aes_cbc::{aes128_cbc_decode, aes128_cbc_encode},
        padding::remove_pkcs7_padding,
    },
    s04::sha1::sha1,
    util::generators::generate_aes_key,
};

use super::dh::*;

pub struct Participant {
    private_key: Option<BigUint>,
    p: Option<BigUint>,
    session_key: Option<[u8; 16]>,
}

impl Participant {
    pub fn new() -> Participant {
        Participant {
            private_key: None,
            p: None,
            session_key: None,
        }
    }

    pub fn send_first_message(&mut self, p: &BigUint, g: &BigUint) -> (BigUint, BigUint, BigUint) {
        let (a_public, a_private) = generate_dh_key(p, g);
        self.private_key = Some(a_private);
        self.p = Some(p.clone());
        (p.clone(), g.clone(), a_public)
    }
    pub fn receive_first_message(&mut self, a: &BigUint) {
        let shared_secret = generate_session_key(
            a,
            &self.private_key.as_ref().unwrap(),
            &self.p.as_ref().unwrap(),
        );
        let hash = sha1(&shared_secret.to_bytes_be());
        self.session_key = Some(hash[0..16].try_into().unwrap());
    }
    pub fn encrypt_message(&self, plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let iv = generate_aes_key();
        (
            iv.clone(),
            aes128_cbc_encode(plain, &self.session_key.unwrap(), &iv),
        )
    }
    pub fn decrypt_message(&self, iv: &[u8], cipher: &[u8]) -> Vec<u8> {
        let out = aes128_cbc_decode(cipher, &self.session_key.unwrap(), iv);
        remove_pkcs7_padding(&out).expect("invalid padding")
    }
}

pub fn get_session_key_for(shared_secret: BigUint) -> [u8; 16] {
    let hash = sha1(&shared_secret.to_bytes_be());
    hash[0..16].try_into().unwrap()
}

#[cfg(test)]
mod tests {

    use crate::s05::dh::get_nist_g;

    use super::*;

    #[test]
    fn s05e02_good() {
        let message = "Hello World!";
        let mut alice = Participant::new();
        let mut bob = Participant::new();

        let (p_a, g_a, a_a) = alice.send_first_message(&get_nist_p(), &get_nist_g());
        let (_p_b, _g_b, a_b) = bob.send_first_message(&p_a, &g_a);

        alice.receive_first_message(&a_b);
        bob.receive_first_message(&a_a);

        let (iv, cipher) = alice.encrypt_message(message.as_bytes());
        let decrypted = bob.decrypt_message(&iv, &cipher);

        assert_eq!(message, std::str::from_utf8(&decrypted).unwrap());
    }

    #[test]
    fn s05e02_mitm() {
        let message = "Hello World!";
        let mut alice = Participant::new();
        let mut bob = Participant::new();

        let (p_a, g_a, _a_a) = alice.send_first_message(&get_nist_p(), &get_nist_g());
        let (_p_b, _g_b, _a_b) = bob.send_first_message(&p_a, &g_a);

        alice.receive_first_message(&get_nist_p());
        bob.receive_first_message(&get_nist_p());

        let (iv, cipher) = alice.encrypt_message(message.as_bytes());
        let decrypted = bob.decrypt_message(&iv, &cipher);

        assert_eq!(message, std::str::from_utf8(&decrypted).unwrap());

        let session_key = get_session_key_for(BigUint::from(0u8));

        let out = aes128_cbc_decode(&cipher, &session_key, &iv);
        let decrypted_mal = remove_pkcs7_padding(&out).expect("invalid padding");

        assert_eq!(message, std::str::from_utf8(&decrypted_mal).unwrap())
    }

    #[test]
    fn s05e03_g_is_one() {
        let message = "Hello World!";
        let mut alice = Participant::new();
        let mut bob = Participant::new();

        let (p_a, g_a, a_a) = alice.send_first_message(&get_nist_p(), &BigUint::from(1u8));
        let (_p_b, _g_b, a_b) = bob.send_first_message(&p_a, &g_a);

        alice.receive_first_message(&a_b);
        bob.receive_first_message(&a_a);

        let (iv, cipher) = alice.encrypt_message(message.as_bytes());
        let decrypted = bob.decrypt_message(&iv, &cipher);

        assert_eq!(message, std::str::from_utf8(&decrypted).unwrap());

        let session_key = get_session_key_for(BigUint::from(1u8));

        let out = aes128_cbc_decode(&cipher, &session_key, &iv);
        let decrypted_mal = remove_pkcs7_padding(&out).expect("invalid padding");

        assert_eq!(message, std::str::from_utf8(&decrypted_mal).unwrap())
    }

    #[test]
    fn s05e03_g_is_p() {
        let message = "Hello World!";
        let mut alice = Participant::new();
        let mut bob = Participant::new();

        let (p_a, g_a, a_a) = alice.send_first_message(&get_nist_p(), &get_nist_p());
        let (_p_b, _g_b, a_b) = bob.send_first_message(&p_a, &g_a);

        alice.receive_first_message(&a_b);
        bob.receive_first_message(&a_a);

        let (iv, cipher) = alice.encrypt_message(message.as_bytes());
        let decrypted = bob.decrypt_message(&iv, &cipher);

        assert_eq!(message, std::str::from_utf8(&decrypted).unwrap());

        let session_key = get_session_key_for(BigUint::from(0u8));

        let out = aes128_cbc_decode(&cipher, &session_key, &iv);
        let decrypted_mal = remove_pkcs7_padding(&out).expect("invalid padding");

        assert_eq!(message, std::str::from_utf8(&decrypted_mal).unwrap())
    }

    #[test]
    fn s05e03_g_is_p_minus_one() {
        let message = "Hello World!";
        let mut alice = Participant::new();
        let mut bob = Participant::new();

        let p_minus_one = get_nist_p() - BigUint::from(1u8);

        let (p_a, g_a, a_a) = alice.send_first_message(&get_nist_p(), &p_minus_one);
        let (_p_b, _g_b, a_b) = bob.send_first_message(&p_a, &g_a);

        alice.receive_first_message(&a_b);
        bob.receive_first_message(&a_a);

        let (iv, cipher) = alice.encrypt_message(message.as_bytes());
        let decrypted = bob.decrypt_message(&iv, &cipher);

        assert_eq!(message, std::str::from_utf8(&decrypted).unwrap());

        let session_key;
        if a_a == BigUint::from(1u8) || a_b == BigUint::from(1u8) {
            session_key = get_session_key_for(BigUint::from(1u8));
        } else {
            session_key = get_session_key_for(p_minus_one);
        }

        let out = aes128_cbc_decode(&cipher, &session_key, &iv);
        let decrypted_mal = remove_pkcs7_padding(&out).expect("invalid padding");

        assert_eq!(message, std::str::from_utf8(&decrypted_mal).unwrap())
    }
}
