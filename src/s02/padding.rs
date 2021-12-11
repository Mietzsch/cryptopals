use std::fmt;

pub fn pkcs7_padding(text: &[u8], padding_length: usize) -> Vec<u8> {
    let mut res = Vec::<u8>::from(text);

    if text.len() > padding_length {
        panic!("Text length bigger than padding length")
    }

    let length = padding_length - text.len();

    let padding_bytes = length as u8;

    res.append(&mut vec![padding_bytes; padding_bytes as usize]);

    res
}

type Result<T> = std::result::Result<T, PKCS7Error>;

// Define our error types. These may be customized for our error handling cases.
// Now we will be able to write our own errors, defer to an underlying error
// implementation, or do something in between.
#[derive(Debug, Clone)]
pub struct PKCS7Error;

// Generation of an error is completely separate from how it is displayed.
// There's no need to be concerned about cluttering complex logic with the display style.
//
// Note that we don't store any extra info about the errors. This means we can't state
// which string failed to parse without modifying our types to carry that information.
impl fmt::Display for PKCS7Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid pkcs7 padding")
    }
}

pub fn remove_pkcs7_padding(text: &[u8]) -> Result<Vec<u8>> {
    let padding_byte = *text.last().unwrap();
    if padding_byte == 0 {
        return Err(PKCS7Error);
    }
    if padding_byte as usize > text.len() {
        return Err(PKCS7Error);
    }
    let padding_start = text.len() - padding_byte as usize;
    let res = text[0..padding_start].to_vec();
    if text[padding_start..] != vec![padding_byte; padding_byte as usize] {
        return Err(PKCS7Error);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s02e01() {
        let input = String::from("YELLOW SUBMARINE");

        let res = pkcs7_padding(input.as_bytes(), 20);

        assert_eq!("59454c4c4f57205355424d4152494e4504040404", hex::encode(res));
    }

    #[test]
    fn s02e07() {
        let input1 = b"ICE ICE BABY\x04\x04\x04\x04";

        let output1 = remove_pkcs7_padding(input1).unwrap();

        assert_eq!(output1, b"ICE ICE BABY");

        let input2 = b"ICE ICE BABY\x05\x05\x05\x05";

        assert!(remove_pkcs7_padding(input2).is_err());

        let input3 = b"ICE ICE BABY\x01\x02\x03\x04";

        assert!(remove_pkcs7_padding(input3).is_err());
    }
}
