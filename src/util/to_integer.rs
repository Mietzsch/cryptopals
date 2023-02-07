pub fn to_integer(message: &[u8]) -> rug::Integer {
    let h_m = crate::s04::sha1::sha1(message);
    rug::Integer::from_digits(&h_m, rug::integer::Order::Msf)
}
