pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_test() {
        let input1 = "1c0111001f010100061a024b53535009181c";
        let input2 = "686974207468652062756c6c277320657965";

        let bytes1 = hex::decode(input1).expect("decoding failed");
        let bytes2 = hex::decode(input2).expect("decoding failed");

        let xor = xor(&bytes1, &bytes2);

        let out = hex::encode(&xor);

        let reference = "746865206b696420646f6e277420706c6179";

        assert_eq!(out, reference);
    }
}
