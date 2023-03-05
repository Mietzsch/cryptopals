use crate::s05::rsa::{RsaPrivate, RsaPublic};

pub struct RsaParityOracle {
    sk: RsaPrivate,
}

impl RsaParityOracle {
    pub fn plaintext_is_odd(&self, ciphertext: &rug::Integer) -> bool {
        let plain = self.sk.decrypt(ciphertext);
        plain.is_odd()
    }
}

pub fn get_plain_with_parity_oracle(
    oracle: &RsaParityOracle,
    public_key: &RsaPublic,
    ciphertext: &rug::Integer,
    print_values: bool,
) -> Option<rug::Integer> {
    let prec = public_key.n.significant_bits();
    let mut lower = rug::Float::with_val(prec, 0);
    let mut upper = rug::Float::with_val(prec, &public_key.n);
    let mut interval = rug::Float::with_val(prec, &upper - &lower) / 2;

    let exp = rug::Integer::from(2)
        .pow_mod(&public_key.e, &public_key.n)
        .unwrap();
    let mut ct = ciphertext.clone();

    while interval >= 0.5 {
        if print_values {
            print!("\r upper bound: {upper}");
        }
        ct = (ct * &exp) % &public_key.n;

        if oracle.plaintext_is_odd(&ct) {
            lower += &interval;
        } else {
            upper -= &interval;
        }
        interval /= 2;
    }

    let middlepoint: rug::Float = rug::Float::with_val(prec, &upper + &lower) / 2;

    if let Some(result) = middlepoint.to_integer() {
        if print_values {
            println!("\r upper bound: {result}");
        }
        Some(result)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {

    use crate::{s05::rsa::rsa_keygen, util::base_64::Base64};

    use super::*;

    #[test]
    fn s06e06() {
        let (rsa_public, rsa_private) = rsa_keygen(1024);
        let b64_message = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";
        let base64 = Base64::new_from_string(b64_message).unwrap();
        let plaintext = rug::Integer::from_digits(base64.to_bytes(), rug::integer::Order::Msf);
        let ciphertext = rsa_public.encrypt(&plaintext);
        assert!(rsa_private.decrypt(&ciphertext) == plaintext);

        let oracle = RsaParityOracle { sk: rsa_private };

        let attack_result =
            get_plain_with_parity_oracle(&oracle, &rsa_public, &ciphertext, false).unwrap();
        assert_eq!(plaintext, attack_result);

        let recovered_bytes = attack_result.to_digits(rug::integer::Order::Msf);
        let recovered_message = std::str::from_utf8(&recovered_bytes).unwrap();
        println!("Recovered message: {recovered_message}");
    }

    #[test]
    fn rsa_parity_test() {
        let rsa_public = RsaPublic {
            e: rug::Integer::from(3),
            n: rug::Integer::from(44719),
        };

        let rsa_private = RsaPrivate {
            d: rug::Integer::from(29531),
            n: rug::Integer::from(44719),
        };

        let plaintext = rug::Integer::from(25);
        let ciphertext = rsa_public.encrypt(&plaintext);
        assert!(rsa_private.decrypt(&ciphertext) == plaintext);

        let oracle = RsaParityOracle { sk: rsa_private };

        let attack_result =
            get_plain_with_parity_oracle(&oracle, &rsa_public, &ciphertext, true).unwrap();
        assert_eq!(plaintext, attack_result);
    }
}
