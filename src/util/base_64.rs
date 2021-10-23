use std::fmt;

pub struct Base64 {
    base64_string: String,
}

impl Base64 {
    pub fn new(bytes: &[u8]) -> Base64 {
        let mut string = String::new();

        let len = bytes.len();
        let blocks = len / 3;

        for i in 0..blocks {
            let four_chars =
                threebyte_to_string(&bytes[3 * i], &bytes[3 * i + 1], &bytes[3 * i + 2]);
            string.push(four_chars.0);
            string.push(four_chars.1);
            string.push(four_chars.2);
            string.push(four_chars.3);
        }

        let remaining_bytes = len - blocks * 3;

        if remaining_bytes == 1 {
            let null = 0;
            let four_chars = threebyte_to_string(&bytes[blocks * 3], &null, &null);
            string.push(four_chars.0);
            string.push(four_chars.1);
            string.push('=');
            string.push('=');
        }

        if remaining_bytes == 2 {
            let null = 0;
            let four_chars = threebyte_to_string(&bytes[blocks * 3], &bytes[blocks * 3 + 1], &null);
            string.push(four_chars.0);
            string.push(four_chars.1);
            string.push(four_chars.2);
            string.push('=');
        }

        Base64 {
            base64_string: string,
        }
    }
}

impl fmt::Display for Base64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.base64_string)
    }
}

fn threebyte_to_string(b1: &u8, b2: &u8, b3: &u8) -> (char, char, char, char) {
    let mut res = ('0', '0', '0', '0');

    let mut firstbits: u8 = b1.clone();
    let mut tmp;

    firstbits &= 255 - 3;
    firstbits >>= 2;
    res.0 = sixbits_to_char(firstbits);

    let mut secondbits: u8 = b1.clone();
    secondbits &= 3;
    secondbits <<= 4;
    tmp = b2.clone();
    tmp &= 255 - 15;
    tmp >>= 4;
    secondbits += tmp;
    res.1 = sixbits_to_char(secondbits);

    let mut thirdbits: u8 = b2.clone();
    thirdbits &= 15;
    thirdbits <<= 2;
    tmp = b3.clone();
    tmp &= 255 - 63;
    tmp >>= 6;
    thirdbits += tmp;
    res.2 = sixbits_to_char(thirdbits);

    let mut fourthbits = b3.clone();
    fourthbits &= 63;
    res.3 = sixbits_to_char(fourthbits);

    res
}

fn sixbits_to_char(b: u8) -> char {
    match b {
        0 => 'A',
        1 => 'B',
        2 => 'C',
        3 => 'D',
        4 => 'E',
        5 => 'F',
        6 => 'G',
        7 => 'H',
        8 => 'I',
        9 => 'J',
        10 => 'K',
        11 => 'L',
        12 => 'M',
        13 => 'N',
        14 => 'O',
        15 => 'P',
        16 => 'Q',
        17 => 'R',
        18 => 'S',
        19 => 'T',
        20 => 'U',
        21 => 'V',
        22 => 'W',
        23 => 'X',
        24 => 'Y',
        25 => 'Z',
        26 => 'a',
        27 => 'b',
        28 => 'c',
        29 => 'd',
        30 => 'e',
        31 => 'f',
        32 => 'g',
        33 => 'h',
        34 => 'i',
        35 => 'j',
        36 => 'k',
        37 => 'l',
        38 => 'm',
        39 => 'n',
        40 => 'o',
        41 => 'p',
        42 => 'q',
        43 => 'r',
        44 => 's',
        45 => 't',
        46 => 'u',
        47 => 'v',
        48 => 'w',
        49 => 'x',
        50 => 'y',
        51 => 'z',
        52 => '0',
        53 => '1',
        54 => '2',
        55 => '3',
        56 => '4',
        57 => '5',
        58 => '6',
        59 => '7',
        60 => '8',
        61 => '9',
        62 => '+',
        63 => '/',
        _ => panic!("no valid string"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_with_zero_remainder() {
        let input  = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let bytes = hex::decode(input).expect("decoding failed");
        let base64 = Base64::new(&bytes);

        assert_eq!(
            base64.base64_string,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }
    #[test]
    fn encoding_with_one_remainder() {
        let input = "f";
        let bytes = input.as_bytes();
        let base64 = Base64::new(&bytes);

        assert_eq!(base64.base64_string, "Zg==");
    }
    #[test]
    fn encoding_with_two_remainder() {
        let input = "fo";
        let bytes = input.as_bytes();
        let base64 = Base64::new(&bytes);

        assert_eq!(base64.base64_string, "Zm8=");
    }
}
