use cryptopals::util::xor;
use hex;

fn main() {
    let input1 = "1c0111001f010100061a024b53535009181c";
    let input2 = "686974207468652062756c6c277320657965";

    let bytes1 = hex::decode(input1).expect("decoding failed");
    let bytes2 = hex::decode(input2).expect("decoding failed");

    let xor = xor::xor(&bytes1, &bytes2);

    let out = hex::encode(&xor);

    println!("output is {}", out);
}
