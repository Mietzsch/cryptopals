use num_bigint::{BigInt, BigUint, Sign};

pub fn extended_eucledan(a: &BigUint, b: &BigUint) -> (BigUint, BigInt, BigInt) {
    let mut a = BigInt::from_biguint(Sign::Plus, a.clone());
    let mut b = BigInt::from_biguint(Sign::Plus, b.clone());
    let mut s = BigInt::from(1u8);
    let mut t = BigInt::from(0u8);
    let mut u = BigInt::from(0u8);
    let mut v = BigInt::from(1u8);
    while b != BigInt::from(0u8) {
        let q = &a / &b;
        let b1 = b.clone();
        b = &a - &q * &b;
        a = b1;
        let u1 = u.clone();
        u = &s - &q * &u;
        s = u1;
        let v1 = v.clone();
        v = &t - &q * &v;
        t = v1;
    }
    (a.magnitude().clone(), s, t)
}

pub fn invmod(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (ggt, mut s, _t) = extended_eucledan(a, m);
    if ggt != BigUint::from(1u8) {
        return None;
    }
    let m = BigInt::from_biguint(Sign::Plus, m.clone());
    while s.sign() != Sign::Plus {
        s += &m;
    }
    Some(s.magnitude().clone())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn extended_eucledan_test() {
        let a = BigUint::from(78u8);
        let b = BigUint::from(99u8);

        let (ggt, s, t) = extended_eucledan(&a, &b);

        assert_eq!(ggt, BigUint::from(3u8));
        assert_eq!(s, BigInt::from(14));
        assert_eq!(t, BigInt::from(-11));
    }

    #[test]
    fn invmod_test() {
        let e = BigUint::from(17u8);
        let m = BigUint::from(3120u16);

        let inv = invmod(&e, &m);
        assert_eq!(inv.unwrap(), BigUint::from(2753u16));
    }
}
