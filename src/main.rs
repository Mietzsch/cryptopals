use cryptopals::util::xor;
use hex;
use std::{fs, str};

fn main() {
    println!("preparing map");
    let testdata = fs::read_to_string("data/Shakespeare.txt")
        .expect("Something went wrong reading the shakespeare file");
    let testdata = testdata.replace('\n', "");

    let analyzer = xor::XorAnalyzer::new(&testdata.as_bytes());
    println!("Finished reading map");

    let input = fs::read_to_string("data/set1/4.txt")
        .expect("Something went wrong reading the challenge file");

    let reducer = |previous: (usize, Vec<u8>, f64), str: (usize, &str)| -> (usize, Vec<u8>, f64) {
        let res = analyzer.analyze(&hex::decode(str.1).expect("decoding failed"));
        if res.1 < previous.2 {
            println!("New best: {} in line {}, was {}", res.1, str.0, previous.2);
            (str.0, res.0, res.1)
        } else {
            previous
        }
    };

    let res: (usize, Vec<u8>, f64) = input
        .lines()
        .enumerate()
        .fold((0, vec![], f64::INFINITY), reducer);

    println!(
        "String is \"{}\" with a rating of {} in line {}.",
        str::from_utf8(&res.1).unwrap(),
        res.2,
        res.0
    );
}
