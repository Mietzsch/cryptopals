use std::ops::Sub;

use num_bigint::BigUint;
use num_primes::Generator;

use crate::util::algebra::invmod;

pub struct RsaPublic {
    e: BigUint,
    n: BigUint,
}

impl RsaPublic {
    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        m.modpow(&self.e, &self.n)
    }
}

pub struct RsaPrivate {
    d: BigUint,
    n: BigUint,
}

impl RsaPrivate {
    pub fn decrypt(&self, c: &BigUint) -> BigUint {
        c.modpow(&self.d, &self.n)
    }
}

pub fn rsa_keygen(bits: usize) -> (RsaPublic, RsaPrivate) {
    let mut is_coprime = false;
    let mut n = BigUint::from(0u8);
    let mut e = BigUint::from(0u8);
    let mut d = BigUint::from(0u8);

    while !is_coprime {
        let p = Generator::new_prime(bits);
        let q = Generator::new_prime(bits);

        n = &p * &q;
        let et = (p.sub(1u8)) * (q.sub(1u8));
        e = BigUint::from(3u8);
        if let Some(d_real) = invmod(&e, &et) {
            d = d_real;
            is_coprime = true;
        }
    }

    (RsaPublic { e, n: n.clone() }, RsaPrivate { d, n })
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn rsa() {
        let m = BigUint::from(42u8);

        let (rsa_public, rsa_private) = rsa_keygen(128);

        let c = rsa_public.encrypt(&m);

        let new_m = rsa_private.decrypt(&c);

        assert_eq!(m, new_m);
    }
}
