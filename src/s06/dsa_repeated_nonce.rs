use super::dsa::Signature;
use crate::s06::dsa::DsaPublic;

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

#[cfg(test)]
mod tests {
    use crate::s06::dsa::DsaParameters;

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
        let pk = DsaPublic { y, parameters };

        let mut ms = create_signature_vector(&testdata);

        assert!(check_signatures(&ms, &pk));

        let duplicate_result = find_duplicates(&mut ms);
        assert!(duplicate_result.is_some());
    }
}
