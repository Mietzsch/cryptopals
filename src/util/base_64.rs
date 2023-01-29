use std::fmt;

type Result<T> = std::result::Result<T, Base64Error>;

// Define our error types. These may be customized for our error handling cases.
// Now we will be able to write our own errors, defer to an underlying error
// implementation, or do something in between.
#[derive(Debug, Clone)]
pub struct Base64Error;

// Generation of an error is completely separate from how it is displayed.
// There's no need to be concerned about cluttering complex logic with the display style.
//
// Note that we don't store any extra info about the errors. This means we can't state
// which string failed to parse without modifying our types to carry that information.
impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid character in base64 string")
    }
}

pub struct Base64 {
    bytes: Vec<u8>,
}

impl Base64 {
    pub fn new_from_bytes(bytes: &[u8]) -> Base64 {
        Base64 {
            bytes: bytes.to_vec(),
        }
    }

    pub fn new_from_string(input: &str) -> Result<Base64> {
        let mut bytes = Vec::<u8>::new();

        let byte_array = input.as_bytes();

        let blocks = byte_array.len() / 4;
        if blocks * 4 != byte_array.len() {
            return Err(Base64Error);
        }

        for i in 0..blocks {
            let mut new_bytes = fourbyte_to_bytes(
                &byte_array[i * 4 + 0],
                &byte_array[i * 4 + 1],
                &byte_array[i * 4 + 2],
                &byte_array[i * 4 + 3],
            )?;
            bytes.append(&mut new_bytes);
        }

        Ok(Base64 { bytes })
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn serialize(&self) -> String {
        let mut string = String::new();

        let len = self.bytes.len();
        let blocks = len / 3;

        for i in 0..blocks {
            let four_chars = threebyte_to_string(
                &self.bytes[3 * i],
                &self.bytes[3 * i + 1],
                &self.bytes[3 * i + 2],
            );
            string.push(four_chars.0);
            string.push(four_chars.1);
            string.push(four_chars.2);
            string.push(four_chars.3);
        }

        let remaining_bytes = len - blocks * 3;

        if remaining_bytes == 1 {
            let null = 0;
            let four_chars = threebyte_to_string(&self.bytes[blocks * 3], &null, &null);
            string.push(four_chars.0);
            string.push(four_chars.1);
            string.push('=');
            string.push('=');
        }

        if remaining_bytes == 2 {
            let null = 0;
            let four_chars =
                threebyte_to_string(&self.bytes[blocks * 3], &self.bytes[blocks * 3 + 1], &null);
            string.push(four_chars.0);
            string.push(four_chars.1);
            string.push(four_chars.2);
            string.push('=');
        }

        string
    }
}

impl fmt::Display for Base64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.serialize())
    }
}

fn fourbyte_to_bytes(b1: &u8, b2: &u8, b3: &u8, b4: &u8) -> Result<Vec<u8>> {
    let mut res = Vec::<u8>::new();

    let firstbits = char_to_sixbits(b1)?;
    let mut firstbyte = firstbits << 2;

    let secondbits = char_to_sixbits(b2)?;

    firstbyte |= secondbits >> 4;
    res.push(firstbyte);

    if *b3 != 61 {
        let thirdbits = char_to_sixbits(b3)?;
        let mut secondbyte = secondbits << 4;
        secondbyte |= thirdbits >> 2;
        res.push(secondbyte);

        if *b4 != 61 {
            let fourthbits = char_to_sixbits(b4)?;
            let mut thirdbyte = thirdbits << 6;
            thirdbyte |= fourthbits;
            res.push(thirdbyte);
        }
    }

    Ok(res)
}

fn threebyte_to_string(b1: &u8, b2: &u8, b3: &u8) -> (char, char, char, char) {
    let mut res = ('0', '0', '0', '0');

    let mut firstbits: u8 = *b1;
    let mut tmp;

    firstbits &= 255 - 3;
    firstbits >>= 2;
    res.0 = sixbits_to_char(firstbits);

    let mut secondbits: u8 = *b1;
    secondbits &= 3;
    secondbits <<= 4;
    tmp = *b2;
    tmp &= 255 - 15;
    tmp >>= 4;
    secondbits += tmp;
    res.1 = sixbits_to_char(secondbits);

    let mut thirdbits: u8 = *b2;
    thirdbits &= 15;
    thirdbits <<= 2;
    tmp = *b3;
    tmp &= 255 - 63;
    tmp >>= 6;
    thirdbits += tmp;
    res.2 = sixbits_to_char(thirdbits);

    let mut fourthbits = *b3;
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

fn char_to_sixbits(b: &u8) -> Result<u8> {
    match b {
        65 => Ok(0),
        66 => Ok(1),
        67 => Ok(2),
        68 => Ok(3),
        69 => Ok(4),
        70 => Ok(5),
        71 => Ok(6),
        72 => Ok(7),
        73 => Ok(8),
        74 => Ok(9),
        75 => Ok(10),
        76 => Ok(11),
        77 => Ok(12),
        78 => Ok(13),
        79 => Ok(14),
        80 => Ok(15),
        81 => Ok(16),
        82 => Ok(17),
        83 => Ok(18),
        84 => Ok(19),
        85 => Ok(20),
        86 => Ok(21),
        87 => Ok(22),
        88 => Ok(23),
        89 => Ok(24),
        90 => Ok(25),
        97 => Ok(26),
        98 => Ok(27),
        99 => Ok(28),
        100 => Ok(29),
        101 => Ok(30),
        102 => Ok(31),
        103 => Ok(32),
        104 => Ok(33),
        105 => Ok(34),
        106 => Ok(35),
        107 => Ok(36),
        108 => Ok(37),
        109 => Ok(38),
        110 => Ok(39),
        111 => Ok(40),
        112 => Ok(41),
        113 => Ok(42),
        114 => Ok(43),
        115 => Ok(44),
        116 => Ok(45),
        117 => Ok(46),
        118 => Ok(47),
        119 => Ok(48),
        120 => Ok(49),
        121 => Ok(50),
        122 => Ok(51),
        48 => Ok(52),
        49 => Ok(53),
        50 => Ok(54),
        51 => Ok(55),
        52 => Ok(56),
        53 => Ok(57),
        54 => Ok(58),
        55 => Ok(59),
        56 => Ok(60),
        57 => Ok(61),
        43 => Ok(62),
        47 => Ok(63),
        _ => Err(Base64Error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;

    #[test]
    fn encoding_with_zero_remainder() {
        let input  = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let bytes = hex::decode(input).expect("decoding failed");
        let base64 = Base64::new_from_bytes(&bytes);

        assert_eq!(
            base64.serialize(),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn decoding_with_zero_remainder() {
        let string =
            String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        let base64 = Base64::new_from_string(&string).unwrap();

        let decoded = base64.to_bytes();

        let input  = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let bytes = hex::decode(input).expect("decoding failed");

        assert_eq!(decoded, bytes);
    }

    #[test]
    fn encoding_with_two_remainder() {
        let input = "f";
        let bytes = input.as_bytes();
        let base64 = Base64::new_from_bytes(bytes);

        assert_eq!(base64.serialize(), "Zg==");
    }

    #[test]
    fn decoding_with_two_remainder() {
        let string = String::from("Zg==");
        let base64 = Base64::new_from_string(&string).unwrap();

        let decoded = base64.to_bytes();

        assert_eq!(str::from_utf8(decoded).unwrap(), "f");
    }

    #[test]
    fn encoding_with_one_remainder() {
        let input = "fo";
        let bytes = input.as_bytes();
        let base64 = Base64::new_from_bytes(bytes);

        assert_eq!(base64.serialize(), "Zm8=");
    }

    #[test]
    fn decoding_with_one_remainder() {
        let string = String::from("Zm8=");
        let base64 = Base64::new_from_string(&string).unwrap();

        let decoded = base64.to_bytes();

        assert_eq!(str::from_utf8(decoded).unwrap(), "fo");
    }
}
