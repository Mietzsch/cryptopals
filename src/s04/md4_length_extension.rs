use super::md4::{extend_md4, md4_unsafe_keyed_mac};

pub struct MD4Oracle {
    key: Vec<u8>,
}

impl MD4Oracle {
    pub fn new(key: &[u8]) -> MD4Oracle {
        MD4Oracle { key: key.to_vec() }
    }

    pub fn create_mac(&self, message: &[u8]) -> [u8; 16] {
        md4_unsafe_keyed_mac(&self.key, message)
    }

    pub fn is_admin(&self, message: &[u8], mac: &[u8; 16]) -> bool {
        let new_mac = md4_unsafe_keyed_mac(&self.key, message);
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

pub fn hack_md4_oracle(
    orcale: &MD4Oracle,
    old_message: &[u8],
    old_hash: &[u8; 16],
    new_message: &[u8],
) -> Option<(Vec<u8>, [u8; 16])> {
    for i in 0..=32 {
        let (glue_padding, forged_hash) = extend_md4(&old_hash, new_message, i, old_message.len());
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
    fn s04e06() {
        let keylen = rand::thread_rng().gen_range(0..32);
        let mut key = vec![0; keylen];
        rand::thread_rng().fill_bytes(&mut key);

        let sha_oracle = MD4Oracle::new(&key);

        let message = "comment1=cooking MCs;userdata=foo;comment2= like a pound of bacon";

        let mac = sha_oracle.create_mac(message.as_bytes());

        let new_message_end = ";admin=true";

        let (forged_message, forged_hash) = hack_md4_oracle(
            &sha_oracle,
            message.as_bytes(),
            &mac,
            new_message_end.as_bytes(),
        )
        .unwrap();

        assert!(sha_oracle.is_admin(&forged_message, &forged_hash));
    }
}
