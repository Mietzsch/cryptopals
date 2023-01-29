use crate::util::xor::{hamming, key_xor};

use super::xor_analyzer::XorAnalyzer;

use std::str;

pub struct KeyXorAnalyzer {
    xor_analyzer: XorAnalyzer,
}

impl KeyXorAnalyzer {
    pub fn new(input: &[u8]) -> KeyXorAnalyzer {
        KeyXorAnalyzer {
            xor_analyzer: XorAnalyzer::new(input),
        }
    }

    pub fn analyze(
        &self,
        cipher: &[u8],
        max_keylength: usize,
        keys_to_try: usize,
    ) -> (Vec<u8>, f64, Vec<u8>) {
        let mut distances: Vec<(usize, f64)> = (1..max_keylength)
            .map(|keylen| {
                (
                    keylen,
                    (hamming(&cipher[0..keylen], &cipher[keylen..keylen * 2])
                        + hamming(
                            &cipher[keylen * 2..keylen * 3],
                            &cipher[keylen * 3..keylen * 4],
                        )) as f64
                        / (keylen * 2) as f64,
                )
            })
            .collect();

        distances.sort_by(|(_, a2), (_, b2)| a2.partial_cmp(b2).unwrap());

        let mut res = (Vec::<u8>::new(), f64::INFINITY, Vec::<u8>::new());

        for (keylen, score) in &distances[0..keys_to_try] {
            println!("possible size {keylen} with score {score}");

            let fixed_keylen_score = self.analyze_with_fixed_keylen(cipher, *keylen, false);
            if fixed_keylen_score.1 < res.1 {
                res = fixed_keylen_score;
            }
        }

        res
    }

    pub fn analyze_with_fixed_keylen(
        &self,
        cipher: &[u8],
        keylen: usize,
        optimize_first_letter: bool,
    ) -> (Vec<u8>, f64, Vec<u8>) {
        let mut keys = Vec::<u8>::new();

        for i in 0..keylen {
            let ciphertext_vector: Vec<u8> = cipher[i..].iter().cloned().step_by(keylen).collect();
            let res = self.xor_analyzer.analyze(&ciphertext_vector);
            //println!("  Found key {} with score {}", res.2, res.1);
            keys.push(res.2);
        }

        if optimize_first_letter {
            let plain = key_xor(cipher, &keys);

            let score = self.xor_analyzer.score_text(&plain);
            let mut best_score = (score, 0);

            for i in 0..=255 {
                let mut new_key = keys.clone();
                new_key[0] ^= i;

                let new_score = self.xor_analyzer.score_text(&key_xor(cipher, &new_key));
                if new_score < best_score.0 {
                    // println!(
                    //     "Found better score with {}, score {}. Was {}",
                    //     i, new_score, best_score.0,
                    // );
                    best_score = (new_score, i);
                }
            }

            keys[0] ^= best_score.1;
        }

        let plain = key_xor(cipher, &keys);

        let key_str = str::from_utf8(&keys).unwrap_or("NOT UTF8");

        let score = self.xor_analyzer.score_text(&plain);

        println!("    Final score: {score} with key {key_str}");
        (plain, score, keys)
    }
}

#[cfg(test)]
mod tests {
    use crate::util::base_64::Base64;

    use super::*;

    #[test]
    fn s01e06() {
        use std::{fs, str};

        println!("preparing map");
        let testdata = fs::read_to_string("data/Shakespeare.txt")
            .expect("Something went wrong reading the shakespeare file");
        let testdata = testdata.replace('\n', "");

        let analyzer = KeyXorAnalyzer::new(testdata.as_bytes());
        println!("Finished reading map");

        let input = fs::read_to_string("data/set1/6.txt")
            .expect("Something went wrong reading the challenge file");

        let input = input.replace('\n', "");

        let input_bytes = Base64::new_from_string(&input).unwrap();

        let result = analyzer.analyze(input_bytes.to_bytes(), 32, 10);

        assert_eq!(
            str::from_utf8(&result.2).unwrap(),
            "Terminator X: Bring the noise"
        );

        let plain = fs::read_to_string("data/set1/6_plain.txt")
            .expect("Something went wrong reading the challenge file");

        assert_eq!(str::from_utf8(&result.0).unwrap(), plain);
    }
}
