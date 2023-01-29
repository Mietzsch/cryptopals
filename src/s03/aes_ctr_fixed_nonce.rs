use crate::s01::key_xor_analyzer::KeyXorAnalyzer;

pub fn attack_fixed_none(ciphertexts: Vec<Vec<u8>>, analyzer: &KeyXorAnalyzer) -> Vec<Vec<u8>> {
    let least_len =
        ciphertexts.iter().fold(
            usize::MAX,
            |acc, vec| if vec.len() < acc { vec.len() } else { acc },
        );

    let cipher_appended = ciphertexts.iter().fold(Vec::<u8>::new(), |res, vec| {
        let mut truncated = vec.clone();
        truncated.truncate(least_len);
        [res, truncated].concat()
    });

    let analyze_res = analyzer.analyze_with_fixed_keylen(&cipher_appended, least_len, true);

    let mut res = Vec::<Vec<u8>>::new();

    for lines in analyze_res.0.chunks(least_len) {
        res.push(lines.to_vec());
    }
    res
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::util::base_64::Base64;

    use super::*;

    #[test]
    fn s03e04() {
        let testdata = fs::read_to_string("data/Shakespeare.txt")
            .expect("Something went wrong reading the shakespeare file");
        let testdata = testdata.replace('\n', "");

        let plain = fs::read_to_string("data/set3/4.txt")
            .expect("Something went wrong reading the plain file");

        let analyzer = KeyXorAnalyzer::new(testdata.as_bytes());
        println!("Finished reading map");

        let input = fs::read_to_string("data/set3/4_cipher.txt")
            .expect("Something went wrong reading the challenge file");

        let mut input_vec = Vec::<Vec<u8>>::new();
        for line in input.lines() {
            let secret = hex::decode(line).unwrap();
            input_vec.push(secret);
        }

        let decoded_vec = attack_fixed_none(input_vec, &analyzer);

        for item in decoded_vec.iter().zip(plain.lines()) {
            let plain_bytes = Base64::new_from_string(item.1).expect("Base64_failed");
            assert_eq!(*item.0, plain_bytes.to_bytes()[0..item.0.len()]);
        }
    }
}
