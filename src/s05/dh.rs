use rug::Integer;

use crate::util::generators::generate_random_range;

pub fn get_nist_p() -> Integer {
    Integer::from_str_radix(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",
        16,
    ).unwrap()
}

pub fn get_nist_g() -> Integer {
    Integer::from_str_radix("2", 16).unwrap()
}

pub fn generate_dh_key(p: &Integer, g: &Integer) -> (Integer, Integer) {
    let low = Integer::from(1);
    let high = p - Integer::from(1);

    let a = generate_random_range(&low, &high);

    (g.clone().pow_mod(&a, p).unwrap(), a)
}

pub fn generate_session_key(b_public: &Integer, a_private: &Integer, p: &Integer) -> Integer {
    b_public.clone().pow_mod(a_private, p).unwrap()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn s05e01_small() {
        let p = 37;
        let g = 5;
        let (a_public, a_private) = generate_dh_key(&Integer::from(p), &Integer::from(g));
        let (b_public, b_private) = generate_dh_key(&Integer::from(p), &Integer::from(g));

        let s_for_a = generate_session_key(&b_public, &a_private, &Integer::from(p));
        let s_for_b = generate_session_key(&a_public, &b_private, &Integer::from(p));

        assert_eq!(s_for_a, s_for_b);
    }

    #[test]
    fn s05e01_nist() {
        let p = get_nist_p();
        let g = get_nist_g();
        let (a_public, a_private) = generate_dh_key(&p, &g);
        let (b_public, b_private) = generate_dh_key(&p, &g);

        let s_for_a = generate_session_key(&b_public, &a_private, &p);
        let s_for_b = generate_session_key(&a_public, &b_private, &p);

        assert_eq!(s_for_a, s_for_b);

        //println!("{}", s_for_a.to_str_radix(16));
    }
}
