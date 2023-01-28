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

    #[test]
    fn rsa_broadcast() {
        let m = BigUint::from(42u8);
        let strength = 128;

        let (rsa_public_0, _rsa_private_0) = rsa_keygen(strength);
        let (rsa_public_1, _rsa_private_1) = rsa_keygen(strength);
        let (rsa_public_2, _rsa_private_2) = rsa_keygen(strength);

        let c_0 = rsa_public_0.encrypt(&m);
        let c_1 = rsa_public_1.encrypt(&m);
        let c_2 = rsa_public_2.encrypt(&m);

        let n_0 = rsa_public_0.n;
        let n_1 = rsa_public_1.n;
        let n_2 = rsa_public_2.n;

        let m_s_0 = &n_1 * &n_2;
        let m_s_1 = &n_0 * &n_2;
        let m_s_2 = &n_0 * &n_1;

        let inv_0 = invmod(&m_s_0, &n_0).unwrap();
        let inv_1 = invmod(&m_s_1, &n_1).unwrap();
        let inv_2 = invmod(&m_s_2, &n_2).unwrap();

        let addition = (&c_0 * &m_s_0 * inv_0) + (&c_1 * &m_s_1 * inv_1) + (&c_2 * &m_s_2 * inv_2);
        let n123 = &n_0 * &n_1 * &n_2;

        let int = addition % n123;

        let result = int.cbrt();

        assert_eq!(result, m);
    }
}
