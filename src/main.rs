use cryptopals::s01::aes_ecb::aes_ecb_detector;

fn main() {
    use std::fs;

    let input = fs::read_to_string("data/set1/8.txt")
        .expect("Something went wrong reading the challenge file");

    let reducer = |previous: (usize, usize), str: (usize, &str)| -> (usize, usize) {
        let bytes = hex::decode(str.1).expect("decoding failed");
        let res = aes_ecb_detector(&bytes);
        if previous.0 < res {
            println!("New best: {} in line {}, was {}", res, str.0, previous.0);
            (res, str.0)
        } else {
            previous
        }
    };

    let res: (usize, usize) = input.lines().enumerate().fold((0, 0), reducer);

    println!("Most likely line is {} with a value of {}", res.1, res.0);
}
