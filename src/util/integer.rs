pub fn to_integer(message: &[u8]) -> rug::Integer {
    let h_m = crate::s04::sha1::sha1(message);
    from_bytes(&h_m)
}

pub fn to_bytes(integer: &rug::Integer) -> Vec<u8> {
    integer.to_digits(rug::integer::Order::Msf)
}

pub fn from_bytes(message: &[u8]) -> rug::Integer {
    rug::Integer::from_digits(message, rug::integer::Order::Msf)
}

pub fn to_hash(integer: &rug::Integer) -> [u8; 20] {
    let repr = integer.to_digits(rug::integer::Order::Msf);
    let repr_hex = hex::encode(repr);
    crate::s04::sha1::sha1(repr_hex.as_bytes())
}
