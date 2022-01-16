use std::fs;

use cryptopals::s03::mt_rng::MTRng;

fn main() {
    let seed = 1131464071;
    let mut mt_rng = MTRng::new(seed);

    let input =
        fs::read_to_string("data/set3/5.txt").expect("Something went wrong reading the KAT file");

    for line in input.lines() {
        let kat_number = line.parse::<u32>().unwrap();
        if kat_number != mt_rng.extract_number() {
            panic!("numbers dont match");
        } else {
            println!("line matched");
        }
    }
}
