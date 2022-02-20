use std::convert::TryInto;

use crate::util::bits::{u32_to_big_endian, u64_to_big_endian, u8_vector_to_u32};

const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;

pub fn sha1(message: &[u8]) -> [u8; 20] {
    let mut expanded_message = message.to_vec();
    expanded_message.append(&mut get_padding(message.len(), message.len()));
    sha1_expanded_with_hs(&expanded_message, H0, H1, H2, H3, H4)
}

pub fn sha1_unsafe_keyed_mac(key: &[u8], message: &[u8]) -> [u8; 20] {
    sha1(&[key, message].concat())
}

pub fn extend_sha1(
    original_hash: &[u8; 20],
    new_message: &[u8],
    keylen_bytes: usize,
    original_message_bytes: usize,
) -> (Vec<u8>, [u8; 20]) {
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
        sha1_expanded_with_hs(
            &new_expanded_message,
            u8_vector_to_u32(&original_hash[0..4]),
            u8_vector_to_u32(&original_hash[4..8]),
            u8_vector_to_u32(&original_hash[8..12]),
            u8_vector_to_u32(&original_hash[12..16]),
            u8_vector_to_u32(&original_hash[16..20]),
        ),
    )
}

fn sha1_expanded_with_hs(
    message: &[u8],
    h0_in: u32,
    h1_in: u32,
    h2_in: u32,
    h3_in: u32,
    h4_in: u32,
) -> [u8; 20] {
    if message.len() % 64 != 0 {
        panic!("Message len is not a multiple of 512 bit.");
    }
    let mut h0 = h0_in;
    let mut h1 = h1_in;
    let mut h2 = h2_in;
    let mut h3 = h3_in;
    let mut h4 = h4_in;

    for chunk in message.chunks_exact(64) {
        sha1_chunk_loop(chunk, &mut h0, &mut h1, &mut h2, &mut h3, &mut h4);
    }

    [
        u32_to_big_endian(h0),
        u32_to_big_endian(h1),
        u32_to_big_endian(h2),
        u32_to_big_endian(h3),
        u32_to_big_endian(h4),
    ]
    .concat()
    .try_into()
    .unwrap()
}

fn sha1_chunk_loop(
    chunk: &[u8],
    h0: &mut u32,
    h1: &mut u32,
    h2: &mut u32,
    h3: &mut u32,
    h4: &mut u32,
) {
    let mut w = [0; 80];

    for block in chunk.chunks_exact(4).enumerate() {
        w[block.0] = u8_vector_to_u32(block.1);
    }

    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let mut a = *h0;
    let mut b = *h1;
    let mut c = *h2;
    let mut d = *h3;
    let mut e = *h4;

    for i in 0..80 {
        let f;
        let k;

        match i {
            00..=19 => {
                f = (b & c) | ((!b) & d);
                k = 0x5A827999;
            }
            20..=39 => {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            40..=59 => {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            60..=79 => {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            _ => {
                panic!("unreachable")
            }
        }
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    *h0 = (*h0).wrapping_add(a);
    *h1 = (*h1).wrapping_add(b);
    *h2 = (*h2).wrapping_add(c);
    *h3 = (*h3).wrapping_add(d);
    *h4 = (*h4).wrapping_add(e);
}

fn get_padding(true_message_length: usize, padding_message_length: usize) -> Vec<u8> {
    let mut padding = Vec::<u8>::new();
    padding.push(0x80);

    while (padding.len() + true_message_length) % 64 != 56 {
        padding.push(0x00);
    }

    padding.append(&mut u64_to_big_endian((padding_message_length * 8) as u64).into());

    padding
}

#[cfg(test)]
mod tests {

    use crate::util::generators::generate_aes_key;

    use super::*;

    #[test]
    fn sha1_kat() {
        let vec0 = "";
        let sha_value0 = sha1(vec0.as_bytes());

        assert_eq!(
            hex::encode(&sha_value0),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );

        let vec1 = "abc";
        let sha_value1 = sha1(vec1.as_bytes());

        assert_eq!(
            hex::encode(&sha_value1).to_ascii_uppercase(),
            "A9993E364706816ABA3E25717850C26C9CD0D89D"
        );

        let vec2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let sha_value2 = sha1(vec2.as_bytes());

        assert_eq!(
            hex::encode(&sha_value2).to_ascii_uppercase(),
            "84983E441C3BD26EBAAE4AA1F95129E5E54670F1"
        );

        let vec3 = "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern";
        let sha_value3 = sha1(vec3.as_bytes());

        assert_eq!(
            hex::encode(&sha_value3),
            "68ac906495480a3404beee4874ed853a037a7a8f"
        );
    }

    #[test]
    fn sha1_keyed_mac_test() {
        let key = generate_aes_key();
        let message = "asdlksld";

        let mac = sha1_unsafe_keyed_mac(&key, message.as_bytes());

        let tampered_message = "bsdlksld";

        let tampered_mac = sha1_unsafe_keyed_mac(&key, tampered_message.as_bytes());

        assert_ne!(mac, tampered_mac);
    }

    #[test]
    fn sha1_simple_length_extension() {
        let key = generate_aes_key();
        let message = "comment1=cooking MCs;userdata=foo;comment2= like a pound of bacon";

        let mac = sha1_unsafe_keyed_mac(&key, message.as_bytes());

        let new_message_end = ";admin=true";

        let (glue_padding, forged_hash) =
            extend_sha1(&mac, new_message_end.as_bytes(), 16, message.len());
        let forged_message = [
            message.as_bytes(),
            &glue_padding,
            new_message_end.as_bytes(),
        ]
        .concat();

        assert_eq!(sha1_unsafe_keyed_mac(&key, &forged_message), forged_hash);

        let mut is_admin = false;

        for substring in forged_message.split(|byte| *byte == b';') {
            if substring == b"admin=true" {
                is_admin = true;
            }
        }

        assert!(is_admin);
    }
}
