use cryptopals::{s01::key_xor_analyzer::KeyXorAnalyzer, util::base_64::Base64};

fn main() {
    use std::{fs, str};

    println!("preparing map");
    let testdata = fs::read_to_string("data/Shakespeare.txt")
        .expect("Something went wrong reading the shakespeare file");
    //let testdata = testdata.replace('\n', "");

    let analyzer = KeyXorAnalyzer::new(&testdata.as_bytes());
    println!("Finished reading map");

    let input = fs::read_to_string("data/set1/6.txt")
        .expect("Something went wrong reading the challenge file");

    let input = input.replace("\n", "");

    let input_bytes = Base64::new_from_string(&input).unwrap();

    let result = analyzer.analyze(input_bytes.to_bytes(), 32, 10);

    println!(
        "Key was {} and the final score is {}",
        str::from_utf8(&result.2).unwrap(),
        result.1
    );
    println!("Plaintext is:\n{}", str::from_utf8(&result.0).unwrap());

    fs::write("data/set1/6_plain.txt", result.0).unwrap();
}
