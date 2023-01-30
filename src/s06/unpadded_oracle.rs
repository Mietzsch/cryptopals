use std::collections::HashSet;

use rug::Integer;

use crate::s05::rsa::{rsa_keygen, RsaPrivate, RsaPublic};

pub struct Oracle {
    pub public_key: RsaPublic,
    private_key: RsaPrivate,
    seen_ciphertexts: HashSet<Integer>,
}

impl Oracle {
    pub fn new(strength: usize) -> Oracle {
        let (public_key, private_key) = rsa_keygen(strength);
        let seen_ciphertexts = HashSet::new();

        Oracle {
            public_key,
            private_key,
            seen_ciphertexts,
        }
    }

    pub fn encrypt(&mut self, m: &rug::Integer) -> Integer {
        let result = self.public_key.encrypt(m);
        self.seen_ciphertexts.insert(result.clone());
        result
    }

    pub fn decrypt(&self, c: &rug::Integer) -> Option<Integer> {
        if self.seen_ciphertexts.contains(c) {
            println!("I've seen this ciphertext before");
            None
        } else {
            Some(self.private_key.decrypt(c))
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::util::generators::generate_random_range;

    use super::*;

    #[test]
    fn s06e01() {
        let strength = 512;

        let mut oracle = Oracle::new(strength);

        let lower = rug::Integer::from(1);
        let upper = rug::Integer::from(256);

        let secret = generate_random_range(&lower, &upper);

        let c = oracle.encrypt(&secret);

        let decrypted = oracle.decrypt(&c);
        assert_eq!(decrypted, None);

        //attack
        let n = oracle.public_key.n.clone();
        let s = rug::Integer::from(2);
        let s_e = oracle.public_key.encrypt(&s);
        let malicious_cipertext = (s_e * c) % &n;

        let new_decrypted = oracle.decrypt(&malicious_cipertext);
        assert!(new_decrypted.is_some());

        let s_inverse = s.invert(&oracle.public_key.n).unwrap();

        let decrypted = (new_decrypted.unwrap() * s_inverse) % &n;

        assert_eq!(decrypted, secret);
    }
}
