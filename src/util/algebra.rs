#[cfg(test)]
mod tests {

    #[test]
    fn extended_eucledan_test() {
        let a = rug::Integer::from(78);
        let b = rug::Integer::from(99);

        let (ggt, s, t) = rug::Integer::extended_gcd(a, b, rug::Integer::new());

        assert_eq!(ggt, rug::Integer::from(3));
        assert_eq!(s, rug::Integer::from(14));
        assert_eq!(t, rug::Integer::from(-11));
    }

    #[test]
    fn invmod_test() {
        let e = rug::Integer::from(17);
        let m = rug::Integer::from(3120);

        let inv = e.invert(&m).unwrap();
        assert_eq!(inv, rug::Integer::from(2753));
    }
}
