pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

pub fn key_xor(plain: &[u8], key: &[u8]) -> Vec<u8> {
    plain
        .iter()
        .enumerate()
        .map(|(pos, byte)| byte ^ key[pos % key.len()])
        .collect()
}

pub fn hamming(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| a ^ b)
        .map(|byte| byte.count_ones())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn xor_test() {
        let input1 = "1c0111001f010100061a024b53535009181c";
        let input2 = "686974207468652062756c6c277320657965";

        let bytes1 = hex::decode(input1).expect("decoding failed");
        let bytes2 = hex::decode(input2).expect("decoding failed");

        let xor = xor(&bytes1, &bytes2);

        let out = hex::encode(xor);

        let reference = "746865206b696420646f6e277420706c6179";

        assert_eq!(out, reference);
    }

    #[test]
    fn s01e05() {
        let line = String::from(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
        );

        let key = String::from("ICE");

        let cipher = key_xor(line.as_bytes(), key.as_bytes());

        let hex_cipher = hex::encode(cipher);

        assert_eq!(hex_cipher, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    }
    #[test]
    fn hamming_test() {
        let string1 = String::from("this is a test");
        let string2 = String::from("wokka wokka!!!");

        let hamming = hamming(string1.as_bytes(), string2.as_bytes());

        assert_eq!(hamming, 37);
    }
}
