use std::{
    cmp::{max, min},
    collections::HashSet,
};

use rug::{Integer, Rational};

use crate::{
    s05::rsa::{RsaPrivate, RsaPublic},
    util::integer::to_bytes,
};

impl RsaPublic {
    pub fn encrypt_pkcs1_5(&self, plain: &[u8]) -> Option<Integer> {
        let k = self.n.significant_digits::<u8>();
        if k < plain.len() + 11 {
            return None;
        }
        let mut padded_bytes = vec![0; k];
        padded_bytes[0] = 0;
        padded_bytes[1] = 2;

        let ps_len = k - 3 - plain.len();
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padded_bytes[2..2 + ps_len]);
        for e in &mut padded_bytes[2..2 + ps_len] {
            if *e == 0 {
                *e = 1;
            }
        }
        padded_bytes[ps_len + 2] = 0;
        padded_bytes[ps_len + 3..].copy_from_slice(plain);

        Some(self.encrypt_bytes(&padded_bytes))
    }
}

impl RsaPrivate {
    pub fn decrypt_pkcs1_5(&self, ciphertext: &Integer) -> Option<Vec<u8>> {
        let k = self.n.significant_digits::<u8>();
        let mut decrypted_bytes = self.decrypt_bytes(ciphertext);
        if decrypted_bytes.len() < k {
            decrypted_bytes.insert(0, 0);
        }

        if decrypted_bytes[0] != 0 || decrypted_bytes[1] != 2 {
            return None;
        }

        let mut iter = decrypted_bytes.iter();
        iter.next();

        let end_of_padding = iter.position(|&x| x == 0)?;

        Some(decrypted_bytes[end_of_padding + 2..].to_vec())
    }
}

pub struct Pkcs15Oracle {
    sk: RsaPrivate,
    tries: Integer,
}

impl Pkcs15Oracle {
    pub fn has_correct_padding(&mut self, ciphertext: &rug::Integer) -> bool {
        self.tries += 1;
        let decrypt = self.sk.decrypt_pkcs1_5(ciphertext);
        decrypt.is_some()
    }

    pub fn print_tries(&self) {
        let log2 = self.tries.significant_bits();
        println!("Took 2^{log2} oracle invocations");
    }
}

fn is_finished(m: &HashSet<(Integer, Integer)>) -> bool {
    if m.len() != 1 {
        return false;
    }
    let last_interval = m.iter().next().unwrap();
    last_interval.0 == last_interval.1
}

fn check_s_i(
    ciphertext: &rug::Integer,
    s: &rug::Integer,
    public_key: &RsaPublic,
    oracle: &mut Pkcs15Oracle,
) -> bool {
    let new_ciper =
        ciphertext * s.clone().pow_mod(&public_key.e, &public_key.n).unwrap() % &public_key.n;
    oracle.has_correct_padding(&new_ciper)
}

pub fn remove_padding(cleartext: &Integer, public_key: &RsaPublic) -> Vec<u8> {
    let k = public_key.n.significant_digits::<u8>();
    let mut bytes = to_bytes(cleartext);
    if bytes.len() < k {
        bytes.insert(0, 0);
    }

    if bytes[0] != 0 || bytes[1] != 2 {
        panic!("not a valid padding");
    }

    let mut iter = bytes.iter();
    iter.next();

    let end_of_padding = iter.position(|&x| x == 0).unwrap();

    bytes[end_of_padding + 2..].to_vec()
}

pub fn get_plain_with_pkcs15_oracle(
    oracle: &mut Pkcs15Oracle,
    public_key: &RsaPublic,
    ciphertext: &rug::Integer,
) -> Integer {
    //Step 1
    if !oracle.has_correct_padding(ciphertext) {
        panic!("ciphertext itself has incorrect padding! Not implemented");
    }
    let k = public_key.n.significant_digits::<u8>();
    let b = rug::Integer::from(1) << (8 * k - 16);
    let two_b: Integer = 2 * b.clone();
    let three_b: Integer = 3 * b;

    let mut first_set = HashSet::new();
    first_set.insert((two_b.clone(), three_b.clone() - 1));
    let mut m = Vec::new();
    m.push(first_set);
    let mut i = 1;
    let mut s = Vec::new();
    s.push(Integer::from(1));

    while !is_finished(&m[i - 1]) {
        //Step 2
        if i == 1 {
            //Step 2.a
            let start = Rational::from((&public_key.n, &three_b));
            let mut new_s = start.ceil().numer().to_owned();
            while !check_s_i(ciphertext, &new_s, public_key, oracle) {
                new_s += 1;
            }
            s.push(new_s);
        } else if m[i - 1].len() > 1 {
            //Step 2.b
            let mut new_s = s[i - 1].clone() + 1;
            while !check_s_i(ciphertext, &new_s, public_key, oracle) {
                new_s += 1;
            }
            s.push(new_s);
        } else {
            //Step 2.c
            let (a, b) = &m[i - 1].iter().next().unwrap();
            let start_r: Rational =
                2 * Rational::from((b.clone() * &s[i - 1] - &two_b, &public_key.n));
            let mut r = start_r.ceil().numer().to_owned();
            let mut new_s = Integer::from(0);
            let mut found_new_s = false;
            while !found_new_s {
                let lower_interval = Rational::from((r.clone() * &public_key.n + &two_b, b));
                let upper_interval = Rational::from((r.clone() * &public_key.n + &three_b, a));
                new_s = lower_interval.ceil().numer().to_owned();
                while new_s < upper_interval {
                    if check_s_i(ciphertext, &new_s, public_key, oracle) {
                        found_new_s = true;
                        break;
                    }
                    new_s += 1;
                }
                r += 1;
            }
            s.push(new_s);
        }

        // Step 3
        let mut current_set = HashSet::new();
        for (a, b) in &m[i - 1] {
            let lower_r = Rational::from((a.clone() * &s[i] - &three_b + 1, &public_key.n));
            let upper_r = Rational::from((b.clone() * &s[i] - &two_b, &public_key.n));

            let mut r = lower_r.ceil().numer().clone();
            while r <= upper_r {
                let a_candidate = Rational::from((r.clone() * &public_key.n + &two_b, &s[i]))
                    .ceil()
                    .numer()
                    .to_owned();
                let new_a = max(a, &a_candidate);

                let b_candidate = Rational::from((r.clone() * &public_key.n + &three_b - 1, &s[i]))
                    .floor()
                    .numer()
                    .to_owned();
                let new_b = min(b, &b_candidate);

                if new_a <= new_b {
                    current_set.insert((new_a.to_owned(), new_b.to_owned()));
                }
                r += 1;
            }
        }
        m.push(current_set);
        i += 1;
    }

    m.last().unwrap().iter().next().unwrap().0.clone()
}

#[cfg(test)]
mod tests {

    use crate::s05::rsa::rsa_keygen;

    use super::*;

    #[test]
    fn pkcs1_5_padding() {
        let (rsa_public, rsa_private) = rsa_keygen(256);

        let message = "kick it, CC";

        let c = rsa_public.encrypt_pkcs1_5(message.as_bytes()).unwrap();
        let decrypted = rsa_private.decrypt_pkcs1_5(&c).unwrap();

        assert_eq!(message.as_bytes(), decrypted);

        let c_tampered = c * 2;
        assert!(rsa_private.decrypt_pkcs1_5(&c_tampered).is_none())
    }

    #[test]
    fn pkcs1_5_padding_oracle() {
        let (rsa_public, rsa_private) = rsa_keygen(256);

        let mut oracle = Pkcs15Oracle {
            sk: rsa_private,
            tries: Integer::from(0),
        };

        let message = "kick it, CC";

        let c = rsa_public.encrypt_pkcs1_5(message.as_bytes()).unwrap();
        let m = get_plain_with_pkcs15_oracle(&mut oracle, &rsa_public, &c);

        let decrypted = remove_padding(&m, &rsa_public);
        assert_eq!(decrypted, message.as_bytes());
        oracle.print_tries();
    }

    #[test]
    #[ignore]
    fn pkcs1_5_padding_oracle_large() {
        let (rsa_public, rsa_private) = rsa_keygen(1024);

        let mut oracle = Pkcs15Oracle {
            sk: rsa_private,
            tries: Integer::from(0),
        };

        let message = "kick it, CC";

        let c = rsa_public.encrypt_pkcs1_5(message.as_bytes()).unwrap();
        let m = get_plain_with_pkcs15_oracle(&mut oracle, &rsa_public, &c);

        let decrypted = remove_padding(&m, &rsa_public);
        assert_eq!(decrypted, message.as_bytes());
        oracle.print_tries();
    }
}
