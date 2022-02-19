use crate::s02::aes_cbc::{aes128_cbc_decode, aes128_cbc_encode};

pub struct CBCOracle {
    key: Vec<u8>,
}

impl CBCOracle {
    pub fn new(key: &[u8]) -> CBCOracle {
        CBCOracle { key: key.to_vec() }
    }

    pub fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
        aes128_cbc_encode(plain, &self.key, &self.key)
    }

    pub fn decrypt(&self, cipher: &[u8]) -> Vec<u8> {
        aes128_cbc_decode(cipher, &self.key, &self.key)
    }
}

#[cfg(test)]
mod tests {

    use rand::{thread_rng, RngCore};

    use crate::util::{generators::generate_aes_key, xor::xor};

    use super::*;

    #[test]
    fn s04e03() {
        let key = generate_aes_key();
        let oracle = CBCOracle::new(&key);

        let mut plain = vec![0; 3 * 16];

        thread_rng().fill_bytes(&mut plain);

        let cipher = oracle.encrypt(&plain);

        let tampered_cipher = [&cipher[0..16], &vec![0; 16], &cipher[0..16]].concat();

        let tampered_plain = oracle.decrypt(&tampered_cipher);

        let recovered_key = xor(&tampered_plain[0..16], &tampered_plain[32..48]);

        assert_eq!(recovered_key, key);
    }
}
