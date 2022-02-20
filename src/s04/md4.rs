use std::convert::TryInto;

use crate::util::bits::{u32_to_little_endian, u64_to_little_endian, u8_vector_to_u32_reverse};

const A: u32 = 0x67452301;
const B: u32 = 0xEFCDAB89;
const C: u32 = 0x98BADCFE;
const D: u32 = 0x10325476;
const E: u32 = 0x5A827999;
const F: u32 = 0x6ED9EBA1;

pub fn md4(message: &[u8]) -> [u8; 16] {
    let mut expanded_message = message.to_vec();
    expanded_message.append(&mut get_padding(message.len(), message.len()));
    md4_expanded(&expanded_message, A, B, C, D)
}

pub fn md4_unsafe_keyed_mac(key: &[u8], message: &[u8]) -> [u8; 16] {
    md4(&[key, message].concat())
}

pub fn extend_md4(
    original_hash: &[u8; 16],
    new_message: &[u8],
    keylen_bytes: usize,
    original_message_bytes: usize,
) -> (Vec<u8>, [u8; 16]) {
    let glue_padding = get_padding(
        keylen_bytes + original_message_bytes,
        keylen_bytes + original_message_bytes,
    );
    let mut new_expanded_message = new_message.to_vec();
    new_expanded_message.append(&mut get_padding(
        new_message.len(),
        keylen_bytes + original_message_bytes + glue_padding.len() + new_message.len(),
    ));
    (
        glue_padding,
        md4_expanded(
            &new_expanded_message,
            u8_vector_to_u32_reverse(&original_hash[0..4]),
            u8_vector_to_u32_reverse(&original_hash[4..8]),
            u8_vector_to_u32_reverse(&original_hash[8..12]),
            u8_vector_to_u32_reverse(&original_hash[12..16]),
        ),
    )
}

fn md4_expanded(message: &[u8], a_in: u32, b_in: u32, c_in: u32, d_in: u32) -> [u8; 16] {
    if message.len() % 64 != 0 {
        panic!("Message len is not a multiple of 512 bit.");
    }
    let mut a = a_in;
    let mut b = b_in;
    let mut c = c_in;
    let mut d = d_in;

    for chunk in message.chunks_exact(64) {
        md4_chunk_loop(chunk, &mut a, &mut b, &mut c, &mut d);
    }

    [
        u32_to_little_endian(a),
        u32_to_little_endian(b),
        u32_to_little_endian(c),
        u32_to_little_endian(d),
    ]
    .concat()
    .try_into()
    .unwrap()
}

fn md4_chunk_loop(chunk: &[u8], a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    let mut x = [0; 16];

    for block in chunk.chunks_exact(4).enumerate() {
        x[block.0] = u8_vector_to_u32_reverse(block.1);
    }

    let aa = *a;
    let bb = *b;
    let cc = *c;
    let dd = *d;

    //round 1
    *a = ((*a).wrapping_add(f(*b, *c, *d)).wrapping_add(x[0])).rotate_left(3);
    *d = ((*d).wrapping_add(f(*a, *b, *c)).wrapping_add(x[1])).rotate_left(7);
    *c = ((*c).wrapping_add(f(*d, *a, *b)).wrapping_add(x[2])).rotate_left(11);
    *b = ((*b).wrapping_add(f(*c, *d, *a)).wrapping_add(x[3])).rotate_left(19);
    *a = ((*a).wrapping_add(f(*b, *c, *d)).wrapping_add(x[4])).rotate_left(3);
    *d = ((*d).wrapping_add(f(*a, *b, *c)).wrapping_add(x[5])).rotate_left(7);
    *c = ((*c).wrapping_add(f(*d, *a, *b)).wrapping_add(x[6])).rotate_left(11);
    *b = ((*b).wrapping_add(f(*c, *d, *a)).wrapping_add(x[7])).rotate_left(19);
    *a = ((*a).wrapping_add(f(*b, *c, *d)).wrapping_add(x[8])).rotate_left(3);
    *d = ((*d).wrapping_add(f(*a, *b, *c)).wrapping_add(x[9])).rotate_left(7);
    *c = ((*c).wrapping_add(f(*d, *a, *b)).wrapping_add(x[10])).rotate_left(11);
    *b = ((*b).wrapping_add(f(*c, *d, *a)).wrapping_add(x[11])).rotate_left(19);
    *a = ((*a).wrapping_add(f(*b, *c, *d)).wrapping_add(x[12])).rotate_left(3);
    *d = ((*d).wrapping_add(f(*a, *b, *c)).wrapping_add(x[13])).rotate_left(7);
    *c = ((*c).wrapping_add(f(*d, *a, *b)).wrapping_add(x[14])).rotate_left(11);
    *b = ((*b).wrapping_add(f(*c, *d, *a)).wrapping_add(x[15])).rotate_left(19);

    //round 2
    *a = ((*a).wrapping_add(g(*b, *c, *d)).wrapping_add(x[0])).rotate_left(3);
    *d = ((*d).wrapping_add(g(*a, *b, *c)).wrapping_add(x[4])).rotate_left(5);
    *c = ((*c).wrapping_add(g(*d, *a, *b)).wrapping_add(x[8])).rotate_left(9);
    *b = ((*b).wrapping_add(g(*c, *d, *a)).wrapping_add(x[12])).rotate_left(13);
    *a = ((*a).wrapping_add(g(*b, *c, *d)).wrapping_add(x[1])).rotate_left(3);
    *d = ((*d).wrapping_add(g(*a, *b, *c)).wrapping_add(x[5])).rotate_left(5);
    *c = ((*c).wrapping_add(g(*d, *a, *b)).wrapping_add(x[9])).rotate_left(9);
    *b = ((*b).wrapping_add(g(*c, *d, *a)).wrapping_add(x[13])).rotate_left(13);
    *a = ((*a).wrapping_add(g(*b, *c, *d)).wrapping_add(x[2])).rotate_left(3);
    *d = ((*d).wrapping_add(g(*a, *b, *c)).wrapping_add(x[6])).rotate_left(5);
    *c = ((*c).wrapping_add(g(*d, *a, *b)).wrapping_add(x[10])).rotate_left(9);
    *b = ((*b).wrapping_add(g(*c, *d, *a)).wrapping_add(x[14])).rotate_left(13);
    *a = ((*a).wrapping_add(g(*b, *c, *d)).wrapping_add(x[3])).rotate_left(3);
    *d = ((*d).wrapping_add(g(*a, *b, *c)).wrapping_add(x[7])).rotate_left(5);
    *c = ((*c).wrapping_add(g(*d, *a, *b)).wrapping_add(x[11])).rotate_left(9);
    *b = ((*b).wrapping_add(g(*c, *d, *a)).wrapping_add(x[15])).rotate_left(13);

    //round 3
    *a = ((*a).wrapping_add(h(*b, *c, *d)).wrapping_add(x[0])).rotate_left(3);
    *d = ((*d).wrapping_add(h(*a, *b, *c)).wrapping_add(x[8])).rotate_left(9);
    *c = ((*c).wrapping_add(h(*d, *a, *b)).wrapping_add(x[4])).rotate_left(11);
    *b = ((*b).wrapping_add(h(*c, *d, *a)).wrapping_add(x[12])).rotate_left(15);
    *a = ((*a).wrapping_add(h(*b, *c, *d)).wrapping_add(x[2])).rotate_left(3);
    *d = ((*d).wrapping_add(h(*a, *b, *c)).wrapping_add(x[10])).rotate_left(9);
    *c = ((*c).wrapping_add(h(*d, *a, *b)).wrapping_add(x[6])).rotate_left(11);
    *b = ((*b).wrapping_add(h(*c, *d, *a)).wrapping_add(x[14])).rotate_left(15);
    *a = ((*a).wrapping_add(h(*b, *c, *d)).wrapping_add(x[1])).rotate_left(3);
    *d = ((*d).wrapping_add(h(*a, *b, *c)).wrapping_add(x[9])).rotate_left(9);
    *c = ((*c).wrapping_add(h(*d, *a, *b)).wrapping_add(x[5])).rotate_left(11);
    *b = ((*b).wrapping_add(h(*c, *d, *a)).wrapping_add(x[13])).rotate_left(15);
    *a = ((*a).wrapping_add(h(*b, *c, *d)).wrapping_add(x[3])).rotate_left(3);
    *d = ((*d).wrapping_add(h(*a, *b, *c)).wrapping_add(x[11])).rotate_left(9);
    *c = ((*c).wrapping_add(h(*d, *a, *b)).wrapping_add(x[7])).rotate_left(11);
    *b = ((*b).wrapping_add(h(*c, *d, *a)).wrapping_add(x[15])).rotate_left(15);

    *a = (*a).wrapping_add(aa);
    *b = (*b).wrapping_add(bb);
    *c = (*c).wrapping_add(cc);
    *d = (*d).wrapping_add(dd);
}

fn get_padding(true_message_length: usize, padding_message_length: usize) -> Vec<u8> {
    let mut padding = Vec::<u8>::new();
    padding.push(0x80);

    while (padding.len() + true_message_length) % 64 != 56 {
        padding.push(0x00);
    }

    padding.append(&mut u64_to_little_endian((padding_message_length * 8) as u64).into());

    padding
}

// f(X,Y,Z)  =  XY v not(X)Z
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

// g(X,Y,Z)  =  XY v XZ v YZ + 5A827999
fn g(x: u32, y: u32, z: u32) -> u32 {
    ((x & y) | (x & z) | (y & z)).wrapping_add(E)
}

// h(X,Y,Z)  =  X xor Y xor Z + 6ED9EBA1
fn h(x: u32, y: u32, z: u32) -> u32 {
    (x ^ y ^ z).wrapping_add(F)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn md4_kat() {
        let vec0 = "";
        let md4_value0 = md4(vec0.as_bytes());

        assert_eq!(hex::encode(&md4_value0), "31d6cfe0d16ae931b73c59d7e0c089c0");

        let vec1 = "a";
        let md4_value1 = md4(vec1.as_bytes());

        assert_eq!(hex::encode(&md4_value1), "bde52cb31de33e46245e05fbdbd6fb24");

        let vec2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let md4_value2 = md4(vec2.as_bytes());

        assert_eq!(hex::encode(&md4_value2), "043f8582f241db351ce627e153e7f0e4");
    }
}
