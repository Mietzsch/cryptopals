use std::collections::HashMap;

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

pub struct XorAnalyzer {
    map: HashMap<u8, f64>,
}

impl XorAnalyzer {
    pub fn analyze(&self, bytes: &[u8]) -> (Vec<u8>, f64) {
        let mut thismap: HashMap<u8, f64> = HashMap::new();

        for byte in bytes {
            let value = thismap.entry(*byte).or_insert(0.0);
            *value += 1.0;
        }

        for (_, val) in thismap.iter_mut() {
            *val /= bytes.len() as f64;
        }

        let mut best_key = 0;
        let mut best_score = f64::INFINITY;

        for key in 0..=255 {
            let score = compute_score(&thismap, key, &self.map);
            if score < best_score {
                best_score = score;
                best_key = key;
            }
        }
        (bytes.iter().map(|a| a ^ best_key).collect(), best_score)
    }

    pub fn new(input: &[u8]) -> XorAnalyzer {
        let mut map: HashMap<u8, f64> = HashMap::new();
        for byte in input {
            let value = map.entry(*byte).or_insert(0.0);
            *value += 1.0;
        }
        for (_, val) in map.iter_mut() {
            *val /= input.len() as f64;
        }
        XorAnalyzer { map: map }
    }
}

fn compute_score(thismap: &HashMap<u8, f64>, key: u8, map: &HashMap<u8, f64>) -> f64 {
    thismap
        .iter()
        .map(|(byte, value)| difference(*byte ^ key, *value, &map))
        .sum::<f64>()
        .sqrt()
}

fn difference(key: u8, value: f64, map: &HashMap<u8, f64>) -> f64 {
    let a = map.get_key_value(&key);
    match a {
        Some((_, v)) => (value - v) * (value - v),
        None => value * value,
    }
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

        let out = hex::encode(&xor);

        let reference = "746865206b696420646f6e277420706c6179";

        assert_eq!(out, reference);
    }

    #[test]
    fn analyzer_test() {
        use std::{fs, str};

        println!("preparing map");
        let testdata = fs::read_to_string("data/Shakespeare.txt")
            .expect("Something went wrong reading the file");
        let testdata = testdata.replace('\n', "");

        let analyzer = XorAnalyzer::new(&testdata.as_bytes());
        println!("Finished reading map");

        let input1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

        let bytes1 = hex::decode(input1).expect("decoding failed");

        let dec = analyzer.analyze(&bytes1).0;
        let dec_str = str::from_utf8(&dec).unwrap();

        assert_eq!(dec_str, "Cooking MC's like a pound of bacon");
    }
    #[test]
    fn s01e04() {
        use std::{fs, str};

        println!("preparing map");
        let testdata = fs::read_to_string("data/Shakespeare.txt")
            .expect("Something went wrong reading the shakespeare file");
        let testdata = testdata.replace('\n', "");

        let analyzer = XorAnalyzer::new(&testdata.as_bytes());
        println!("Finished reading map");

        let input = fs::read_to_string("data/set1/4.txt")
            .expect("Something went wrong reading the challenge file");

        let reducer =
            |previous: (usize, Vec<u8>, f64), str: (usize, &str)| -> (usize, Vec<u8>, f64) {
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
        assert_eq!(
            str::from_utf8(&res.1).unwrap(),
            "Now that the party is jumping\n"
        );
    }
}
