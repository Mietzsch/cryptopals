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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s02e01() {
        let input = String::from("YELLOW SUBMARINE");

        let res = pkcs7_padding(input.as_bytes(), 20);

        assert_eq!("59454c4c4f57205355424d4152494e4504040404", hex::encode(res));
    }
}
