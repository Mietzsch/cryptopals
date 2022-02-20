use std::convert::TryInto;

const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;

pub fn sha1(message: &[u8]) -> [u8; 20] {
    let expanded_message = expand_message(message);
    sha1_expanded_with_hs(&expanded_message, H0, H1, H2, H3, H4)
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

fn expand_message(message: &[u8]) -> Vec<u8> {
    let mut expanded_message = message.to_vec();
    let message_length = (expanded_message.len() * 8) as u64;
    expanded_message.push(0x80);

    while expanded_message.len() % 64 != 56 {
        expanded_message.push(0x00);
    }

    expanded_message.append(&mut u64_to_big_endian(message_length).into());

    expanded_message
}

fn u64_to_big_endian(x: u64) -> [u8; 8] {
    let mut res = [0; 8];
    for i in 0..8 {
        let byte = (x >> (i * 8) & 0xff) as u8;
        res[7 - i] = byte;
    }
    res
}

fn u32_to_big_endian(x: u32) -> [u8; 4] {
    let mut res = [0; 4];
    for i in 0..4 {
        let byte = (x >> (i * 8) & 0xff) as u8;
        res[3 - i] = byte;
    }
    res
}

fn u8_vector_to_u32(vec: &[u8]) -> u32 {
    if vec.len() != 4 {
        panic!("Length should be 4")
    }
    let mut res = 0;
    for i in 0..4 {
        res <<= 8;
        res += vec[i] as u32;
    }
    res
}

#[cfg(test)]
mod tests {

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
}
