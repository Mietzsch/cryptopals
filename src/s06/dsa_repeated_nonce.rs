use super::dsa::{DsaParameters, Signature};
use crate::{s06::dsa::DsaPublic, util::integer::to_integer};

pub struct MessageAndSignature {
    pub message: String,
    pub signature: Signature,
}

pub fn create_signature_vector(input: &str) -> Vec<MessageAndSignature> {
    let element_count = input.lines().count() / 4;
    let mut result = Vec::with_capacity(element_count);
    //unstable: input.lines().array_chunks::<4>()
    let mut lines = input.lines();
    for _ in 0..element_count {
        let msg = lines.next().unwrap();
        let s = lines.next().unwrap();
        let r = lines.next().unwrap();
        lines.next();

        let message = msg.strip_prefix("msg: ").unwrap().to_owned();
        let s_digits = s.strip_prefix("s: ").unwrap();
        let r_digits = r.strip_prefix("r: ").unwrap();

        let s_integer = rug::Integer::from_str_radix(s_digits, 10).unwrap();
        let r_integer = rug::Integer::from_str_radix(r_digits, 10).unwrap();

        let msg_and_sig = MessageAndSignature {
            message,
            signature: Signature {
                r: r_integer,
                s: s_integer,
            },
        };
        result.push(msg_and_sig);
    }
    result
}

pub fn check_signatures(msgs: &[MessageAndSignature], public_key: &DsaPublic) -> bool {
    for ms in msgs {
        if !public_key.verify(ms.message.as_bytes(), &ms.signature) {
            return false;
        }
    }
    true
}

pub fn find_duplicates(
    msgs: &mut [MessageAndSignature],
) -> Option<(&MessageAndSignature, &MessageAndSignature)> {
    msgs.sort_unstable_by(|a, b| a.signature.r.cmp(&b.signature.r));
    for i in 0..msgs.len() - 1 {
        if msgs[i].signature.r == msgs[i + 1].signature.r {
            return Some((&msgs[i], &msgs[i + 1]));
        }
    }
    None
}

pub fn find_k(
    msg1: &MessageAndSignature,
    msg2: &MessageAndSignature,
    parameters: &DsaParameters,
) -> rug::Integer {
    let m1 = to_integer(msg1.message.as_bytes());
    let m2 = to_integer(msg2.message.as_bytes());
    let s1 = &msg1.signature.s;
    let s2 = &msg2.signature.s;
    let q = &parameters.q;

    let numerator = (m1 - m2) % q;
    let denominator = rug::Integer::from(s1 - s2) % q;
    let inverse_denom = denominator.invert(q).unwrap();

    (numerator * inverse_denom) % q
}

#[cfg(test)]
mod tests {
    use crate::s06::dsa::{is_private_key_for, known_k_attack, DsaParameters};

    use super::*;

    #[test]
    fn s06e04() {
        use std::fs;

        let testdata =
            fs::read_to_string("data/set6/44.txt").expect("Something went wrong reading the file");

        let parameters = DsaParameters::default_parameters();
        let y = rug::Integer::from_str_radix(
            "2d026f4bf30195ede3a088da85e398ef869611d0f68f07
            13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
            5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
            f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
            f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
            2971c3de5084cce04a2e147821",
            16,
        )
        .unwrap();
        let pk = DsaPublic {
            y,
            parameters: parameters.clone(),
        };

        let mut ms = create_signature_vector(&testdata);

        assert!(check_signatures(&ms, &pk));

        let duplicate_result = find_duplicates(&mut ms).unwrap();
        let k = find_k(duplicate_result.0, duplicate_result.1, &parameters);

        let x_try = known_k_attack(
            &parameters,
            duplicate_result.0.message.as_bytes(),
            &duplicate_result.0.signature,
            &k,
        );

        assert!(is_private_key_for(&x_try, &pk));

        // let x_hash = to_hash(&x_try);
        // let x_hash_expect =
        //     hex::decode("ca8f6f7c66fa362d40760d135b763eb8527d3d52").expect("decoding failed");
        // assert_eq!(&x_hash[..], x_hash_expect);
    }
}
