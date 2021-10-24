use cryptopals::util::xor;
use hex;
use std::{fs, str};

fn main() {
    println!("preparing map");
    let testdata =
        fs::read_to_string("data/Shakespeare.txt").expect("Something went wrong reading the file");
    let testdata = testdata.replace('\n', "");

    let analyzer = xor::XorAnalyzer::new(&testdata.as_bytes());
    println!("Finished reading map");

    let input1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let bytes1 = hex::decode(input1).expect("decoding failed");

    let dec = analyzer.analyze(&bytes1);
    let dec_str = str::from_utf8(&dec).unwrap();

    println!("String is \"{}\"", dec_str);
}
