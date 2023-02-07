use rug::Integer;

use crate::util::{generators::generate_random_range, to_integer::to_integer};

#[derive(Clone)]
pub struct DsaParameters {
    pub p: Integer,
    pub q: Integer,
    pub g: Integer,
}

impl DsaParameters {
    pub fn default_parameters() -> Self {
        DsaParameters {
             p: rug::Integer::from_str_radix("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16).unwrap(),
             q: rug::Integer::from_str_radix("f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap(),
             g: rug::Integer::from_str_radix("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16).unwrap()
        }
    }
}

pub struct Signature {
    pub r: Integer,
    pub s: Integer,
}

pub struct DsaPublic {
    pub y: Integer,
    pub parameters: DsaParameters,
}

impl DsaPublic {
    pub fn verify(&self, message: &[u8], signature: Signature) -> bool {
        let h_m = to_integer(message);

        let r = &signature.r;
        let s = &signature.s;
        let valid_input = (0 < *r && r < &self.parameters.q) && (0 < *s && s < &self.parameters.q);
        if !valid_input {
            return false;
        }

        let w = s.clone().invert(&self.parameters.q).unwrap();
        let u1 = h_m * &w % &self.parameters.q;
        let u2 = (r * w) % &self.parameters.q;

        let g_u1 = self
            .parameters
            .g
            .clone()
            .pow_mod(&u1, &self.parameters.p)
            .unwrap();
        let g_u2 = self.y.clone().pow_mod(&u2, &self.parameters.p).unwrap();

        let v = g_u1 * g_u2 % &self.parameters.p % &self.parameters.q;
        v == *r
    }
}

pub struct DsaPrivate {
    pub x: Integer,
    pub parameters: DsaParameters,
}

impl DsaPrivate {
    pub fn sign(&self, message: &[u8]) -> Signature {
        let h_m = to_integer(message);

        loop {
            let k = generate_random_range(&rug::Integer::from(2), &self.parameters.q);
            if let Some(sig) = self.sign_with_k(&k, &h_m) {
                return sig;
            }
        }
    }

    pub fn sign_with_chosen_k(&self, message: &[u8], k: &Integer) -> Option<Signature> {
        let h_m = to_integer(message);
        self.sign_with_k(k, &h_m)
    }

    fn sign_with_k(&self, k: &Integer, h_m: &Integer) -> Option<Signature> {
        let r = self
            .parameters
            .g
            .clone()
            .pow_mod(k, &self.parameters.p)
            .unwrap()
            % &self.parameters.q;

        let k_inv = k.clone().invert(&self.parameters.q).unwrap();
        let s = &k_inv * rug::Integer::from(h_m + &r * &self.x) % &self.parameters.q;

        if s == 0 {
            return None;
        };
        Some(Signature { r, s })
    }
}

pub fn generate_dsa_key(parameters: &DsaParameters) -> (DsaPublic, DsaPrivate) {
    let x = generate_random_range(&rug::Integer::from(2), &parameters.q);
    let y = parameters.g.clone().pow_mod(&x, &parameters.p).unwrap();
    (
        DsaPublic {
            y,
            parameters: parameters.clone(),
        },
        DsaPrivate {
            x,
            parameters: parameters.clone(),
        },
    )
}

pub fn known_k_attack(
    parameters: &DsaParameters,
    message: &[u8],
    signature: &Signature,
    k: &Integer,
) -> Integer {
    let h_m = to_integer(message);
    let r_inv = signature.r.clone().invert(&parameters.q).unwrap();
    r_inv * (&signature.s * k - h_m) % &parameters.q
}

pub fn is_private_key_for(x: &Integer, pubkey: &DsaPublic) -> bool {
    if let Ok(g_x) = pubkey.parameters.g.clone().pow_mod(x, &pubkey.parameters.p) {
        g_x == pubkey.y
    } else {
        false
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn dsa_keygen() {
        let (dsa_public, dsa_private) = generate_dsa_key(&DsaParameters::default_parameters());

        assert!(dsa_public.y != 0);
        assert!(dsa_private.x > 1);
        assert!(is_private_key_for(&dsa_private.x, &dsa_public));
    }

    #[test]
    fn sign_verify() {
        let parameters = DsaParameters::default_parameters();
        let (dsa_public, dsa_private) = generate_dsa_key(&parameters);

        let message = "abc";

        let signature = dsa_private.sign(message.as_bytes());

        assert!(dsa_public.verify(message.as_bytes(), signature));
    }

    #[test]
    fn known_k_attack_test() {
        let parameters = DsaParameters::default_parameters();
        let (_dsa_public, dsa_private) = generate_dsa_key(&parameters);

        let message = "abc";
        let k = generate_random_range(&rug::Integer::from(2), &parameters.q);

        let signature = dsa_private
            .sign_with_chosen_k(message.as_bytes(), &k)
            .unwrap();

        let x_try = known_k_attack(&parameters, message.as_bytes(), &signature, &k);

        assert!(x_try == dsa_private.x);
    }
}
