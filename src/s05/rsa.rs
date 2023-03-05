use rug::Integer;

use crate::util::{
    generators::generate_prime,
    integer::{from_bytes, to_bytes},
};

pub struct RsaPublic {
    pub e: Integer,
    pub n: Integer,
}

impl RsaPublic {
    pub fn encrypt(&self, m: &Integer) -> Integer {
        m.clone().pow_mod(&self.e, &self.n).unwrap()
    }

    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Integer {
        self.encrypt(&from_bytes(plaintext))
    }
}

pub struct RsaPrivate {
    pub(crate) d: Integer,
    pub(crate) n: Integer,
}

impl RsaPrivate {
    pub fn decrypt(&self, c: &rug::Integer) -> rug::Integer {
        c.clone().pow_mod(&self.d, &self.n).unwrap()
    }

    pub fn decrypt_bytes(&self, c: &rug::Integer) -> Vec<u8> {
        to_bytes(&self.decrypt(c))
    }
}

pub fn rsa_keygen(bits: usize) -> (RsaPublic, RsaPrivate) {
    let mut is_coprime = false;
    let mut n = Integer::from(0);
    let mut d = Integer::from(0);
    let e = Integer::from(3);

    while !is_coprime {
        let p = generate_prime(bits / 2);
        let mut q = generate_prime(bits / 2);
        while p == q {
            q = generate_prime(bits / 2);
            println!("p = {p}, q = {q}");
        }

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

        let (rsa_public, rsa_private) = rsa_keygen(512);

        let c = rsa_public.encrypt(&m);

        let new_m = rsa_private.decrypt(&c);

        assert_eq!(m, new_m);

        //let random_test = generate_random_bigint(512);
        println!("bits: {}", rsa_public.n.significant_bits());
    }

    #[test]
    fn rsa_test() {
        // n = 239^2
        let rsa_public = RsaPublic {
            e: rug::Integer::from(3),
            n: rug::Integer::from(57121),
        };

        let rsa_private = RsaPrivate {
            d: rug::Integer::from(37763),
            n: rug::Integer::from(57121),
        };

        let plaintext = rug::Integer::from(25);
        let ciphertext = rsa_public.encrypt(&plaintext);
        // Die Eulersche Phi-Funktion und die Carmichael-Funktion müssen anders
        // berechnet werden wenn p = q ist. Dann muss ed = 1 mod p(p-1) gelten.
        assert_ne!(rsa_private.decrypt(&ciphertext), plaintext);
    }

    #[test]
    fn rsa_broadcast() {
        let m = Integer::from(42);
        let strength = 2048;

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

    #[test]
    fn rsa_bytes() {
        let (rsa_public, rsa_private) = rsa_keygen(1024);
        let message = "Hello World!";
        let cipertext = rsa_public.encrypt_bytes(message.as_bytes());

        let plaintext = rsa_private.decrypt_bytes(&cipertext);
        let recovered_message = std::str::from_utf8(&plaintext).unwrap();
        assert_eq!(message, recovered_message);
    }
}
