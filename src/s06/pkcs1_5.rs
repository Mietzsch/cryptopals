use rug::Integer;

use crate::s05::rsa::{RsaPrivate, RsaPublic};

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
}
