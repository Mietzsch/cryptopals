use super::sha1::{extend_sha1, sha1_unsafe_keyed_mac};

pub struct SHA1Oracle {
    key: Vec<u8>,
}

impl SHA1Oracle {
    pub fn new(key: &[u8]) -> SHA1Oracle {
        SHA1Oracle { key: key.to_vec() }
    }

    pub fn create_mac(&self, message: &[u8]) -> [u8; 20] {
        sha1_unsafe_keyed_mac(&self.key, message)
    }

    pub fn is_admin(&self, message: &[u8], mac: &[u8; 20]) -> bool {
        let new_mac = sha1_unsafe_keyed_mac(&self.key, message);
        if new_mac != *mac {
            return false;
        }

        for substring in message.split(|byte| *byte == b';') {
            if substring == b"admin=true" {
                return true;
            }
        }

        return false;
    }
}

pub fn hack_sha1_oracle(
    orcale: &SHA1Oracle,
    old_message: &[u8],
    old_hash: &[u8; 20],
    new_message: &[u8],
) -> Option<(Vec<u8>, [u8; 20])> {
    for i in 0..=32 {
        let (glue_padding, forged_hash) = extend_sha1(&old_hash, new_message, i, old_message.len());
        let forged_message = [old_message, &glue_padding, new_message].concat();
        if orcale.is_admin(&forged_message, &forged_hash) {
            return Some((forged_message, forged_hash));
        }
    }
    None
}

#[cfg(test)]
mod tests {

    use rand::{Rng, RngCore};

    use super::*;

    #[test]
    fn s04e05() {
        let keylen = rand::thread_rng().gen_range(0..32);
        let mut key = vec![0; keylen];
        rand::thread_rng().fill_bytes(&mut key);

        let sha_oracle = SHA1Oracle::new(&key);

        let message = "comment1=cooking MCs;userdata=foo;comment2= like a pound of bacon";

        let mac = sha_oracle.create_mac(message.as_bytes());

        let new_message_end = ";admin=true";

        let (forged_message, forged_hash) = hack_sha1_oracle(
            &sha_oracle,
            message.as_bytes(),
            &mac,
            new_message_end.as_bytes(),
        )
        .unwrap();

        assert!(sha_oracle.is_admin(&forged_message, &forged_hash));
    }
}
