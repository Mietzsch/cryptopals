use indicatif::{ProgressBar, ProgressIterator, ProgressStyle};
use std::collections::{HashMap, HashSet};

use crate::{
    s01::aes_ecb::{aes128_ecb_encode, aes_ecb_detector},
    util::generators::generate_aes_key,
};

pub struct ECBOracle {
    secret: Vec<u8>,
    key: Vec<u8>,
}

impl ECBOracle {
    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let mut new_plain = input.to_vec();
        new_plain.append(&mut self.secret.clone());
        aes128_ecb_encode(&new_plain, &self.key)
    }
}

pub fn decrypt_ecb_simple(input: &[u8]) -> Vec<u8> {
    println!("Starting simple ECB decryption");

    let mut result = Vec::new();
    let oracle = ECBOracle {
        secret: input.to_vec(),
        key: generate_aes_key(),
    };

    let (blocksize, blocks) = get_blocksize(&oracle);
    println!(" blocksize: {}, blocks: {}...", blocksize, blocks);

    let count = aes_ecb_detector(&oracle.encrypt(&vec![0; 10 * blocksize]));
    if count >= 5 {
        println!(" detected ECB...");
    } else {
        panic!("Oracle does not encrypt ECB");
    }

    let mut previous_block = vec![0; blocksize];

    println!(" decrypting blocks...");

    let pb = ProgressBar::new(blocks as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} ({eta})")
            .progress_chars("#>-"),
    );

    for i in (0..blocks).progress_with(pb) {
        let decrypted_block = decrypt_block(&oracle, blocksize, i, &previous_block);
        previous_block = decrypted_block;
        result.append(&mut previous_block.clone());
    }

    result
}

fn get_blocksize(oracle: &ECBOracle) -> (usize, usize) {
    let mut lengthset = HashSet::new();

    for i in 0..64 {
        lengthset.insert(oracle.encrypt(&vec![0; i]).len());
    }

    let mut sizes: Vec<usize> = lengthset.into_iter().collect();
    sizes.sort();

    let diff = sizes[1] - sizes[0];

    for chunk in sizes.chunks(2) {
        if chunk.len() == 2 {
            let diff_new = chunk[1] - chunk[0];
            if diff_new != diff {
                panic!()
            }
        }
    }
    (diff, sizes[0] / diff)
}

fn decrypt_block(
    oracle: &ECBOracle,
    blocksize: usize,
    block: usize,
    previous_block: &[u8],
) -> Vec<u8> {
    let mut result = previous_block.to_vec();
    let mut map: HashMap<Vec<u8>, u8> = HashMap::new();

    let start_pos = block * blocksize;
    let end_pos = (block + 1) * blocksize;

    for byte_offset in 1..=blocksize {
        result.rotate_left(1);

        for i in 0..=255 {
            result[blocksize - 1] = i;
            map.insert(oracle.encrypt(&result)[0..blocksize].to_vec(), i);
        }

        let encr = oracle.encrypt(&result[0..blocksize - byte_offset])[start_pos..end_pos].to_vec();

        let byte = *map.get(&encr).unwrap();

        if byte == 1 {
            result.rotate_left(blocksize - byte_offset);
            result.truncate(byte_offset - 1);
            return result;
        } else {
            result[blocksize - 1] = byte;
        }
    }

    result
}

#[cfg(test)]
mod tests {

    use std::{fs, str::from_utf8};

    use crate::util::base_64::Base64;

    use super::*;

    #[test]
    fn s02e04() {
        let input = fs::read_to_string("data/set2/4.txt")
            .expect("Something went wrong reading the challenge file");
        let input = input.replace("\n", "");

        let dec = decrypt_ecb_simple(Base64::new_from_string(&input).unwrap().to_bytes());

        let dec_str = from_utf8(&dec).unwrap();

        let plain = fs::read_to_string("data/set2/4_plain.txt")
            .expect("Something went wrong reading the result file");

        assert_eq!(dec_str, &plain);
    }
}
