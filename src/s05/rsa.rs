use rug::Integer;

pub struct RsaPublic {
    e: Integer,
    n: Integer,
}

impl RsaPublic {
    pub fn encrypt(&self, m: &Integer) -> Integer {
        m.clone().pow_mod(&self.e, &self.n).unwrap()
    }
}

pub struct RsaPrivate {
    d: Integer,
    n: Integer,
}

impl RsaPrivate {
    pub fn decrypt(&self, c: &rug::Integer) -> rug::Integer {
        c.clone().pow_mod(&self.d, &self.n).unwrap()
    }
}

pub fn generate_prime(bits: usize) -> Integer {
    loop {
        let mut random_vec = vec![0u8; bits / 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_vec);
        let candidate = Integer::from_digits(&random_vec, rug::integer::Order::Lsf);
        if candidate.is_probably_prime(30) != rug::integer::IsPrime::No {
            return candidate;
        }
    }
}

pub fn rsa_keygen(bits: usize) -> (RsaPublic, RsaPrivate) {
    let mut is_coprime = false;
    let mut n = Integer::from(0);
    let mut d = Integer::from(0);
    let e = Integer::from(3);

    while !is_coprime {
        let p = generate_prime(bits);
        let q = generate_prime(bits);

        n = Integer::from(&p * &q);
        let et = (p - 1) * (q - 1);
        if let Ok(d_real) = e.clone().invert(&et) {
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
        let m = Integer::from(42);

        let (rsa_public, rsa_private) = rsa_keygen(16);

        let c = rsa_public.encrypt(&m);

        let new_m = rsa_private.decrypt(&c);

        assert_eq!(m, new_m);
    }

    #[test]
    fn rsa_broadcast() {
        let m = Integer::from(42);
        let strength = 1024;

        let (rsa_public_0, _rsa_private_0) = rsa_keygen(strength);
        let (rsa_public_1, _rsa_private_1) = rsa_keygen(strength);
        let (rsa_public_2, _rsa_private_2) = rsa_keygen(strength);

        let c_0 = rsa_public_0.encrypt(&m);
        let c_1 = rsa_public_1.encrypt(&m);
        let c_2 = rsa_public_2.encrypt(&m);

        let n_0 = &rsa_public_0.n;
        let n_1 = &rsa_public_1.n;
        let n_2 = &rsa_public_2.n;

        let m_s_0 = Integer::from(n_1 * n_2);
        let m_s_1 = Integer::from(n_0 * n_2);
        let m_s_2 = Integer::from(n_0 * n_1);

        let inv_0 = m_s_0.clone().invert(n_0).unwrap();
        let inv_1 = m_s_1.clone().invert(n_1).unwrap();
        let inv_2 = m_s_2.clone().invert(n_2).unwrap();

        let addition = (c_0 * m_s_0 * inv_0) + (c_1 * m_s_1 * inv_1) + (c_2 * m_s_2 * inv_2);
        let n123 = Integer::from(n_0 * n_1) * n_2;

        let int = addition % n123;

        let result = int.root(3);

        assert_eq!(result, m);
    }
}
