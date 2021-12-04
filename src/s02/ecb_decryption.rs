use indicatif::{ProgressBar, ProgressIterator, ProgressStyle};
use std::collections::{HashMap, HashSet};

use crate::s01::aes_ecb::{aes128_ecb_encode, aes_ecb_detector};

use super::oracle::EncryptionOracle;

pub struct ECBOracleSimple {
    secret: Vec<u8>,
    key: Vec<u8>,
}

impl ECBOracleSimple {
    pub fn new(secret: &[u8], key: &[u8]) -> ECBOracleSimple {
        ECBOracleSimple {
            secret: secret.to_vec(),
            key: key.to_vec(),
        }
    }
}

impl EncryptionOracle for ECBOracleSimple {
    fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let mut new_plain = input.to_vec();
        new_plain.append(&mut self.secret.clone());
        aes128_ecb_encode(&new_plain, &self.key)
    }
}

pub struct ECBOracleHard {
    secret: Vec<u8>,
    key: Vec<u8>,
    random: Vec<u8>,
}

impl ECBOracleHard {
    pub fn new(secret: &[u8], key: &[u8], random: &[u8]) -> ECBOracleHard {
        ECBOracleHard {
            secret: secret.to_vec(),
            key: key.to_vec(),
            random: random.to_vec(),
        }
    }
}

impl EncryptionOracle for ECBOracleHard {
    fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let mut new_plain = self.random.clone();
        new_plain.append(&mut input.to_vec());
        new_plain.append(&mut self.secret.clone());
        aes128_ecb_encode(&new_plain, &self.key)
    }
}

pub fn decrypt_ecb(oracle: &impl EncryptionOracle) -> Vec<u8> {
    println!("Starting ECB decryption");

    let mut result = Vec::new();

    let blocksize = get_blocksize(oracle);
    println!(" blocksize: {}...", blocksize);

    let count = aes_ecb_detector(&oracle.encrypt(&vec![0; 10 * blocksize]));
    if count >= 5 {
        println!(" detected ECB...");
    } else {
        panic!("Oracle does not encrypt ECB");
    }

    let (random_prefix_length, blocks) = get_random_prefix_length(oracle, blocksize);

    println!(
        " prefix length: {}, plaintext blocks to decrypt: {}...",
        random_prefix_length, blocks
    );

    let mut previous_block = vec![0; blocksize];

    println!(" decrypting blocks...");

    let pb = ProgressBar::new(blocks as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} ETA: {eta}")
            .progress_chars("#>-"),
    );

    for i in (0..blocks).progress_with(pb) {
        let decrypted_block =
            decrypt_block(oracle, blocksize, i, &previous_block, random_prefix_length);
        previous_block = decrypted_block;
        result.append(&mut previous_block.clone());
    }

    println!("Finished ECB decryption");

    result
}

fn get_blocksize(oracle: &impl EncryptionOracle) -> usize {
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
    diff
}

fn get_random_prefix_length(oracle: &impl EncryptionOracle, blocksize: usize) -> (usize, usize) {
    let mut difference_map: HashMap<usize, usize> = HashMap::new();
    for i in 0..blocksize {
        difference_map.insert(
            i,
            aes_ecb_detector(&oracle.encrypt(&vec![0; 10 * blocksize + i])),
        );
    }
    let mut difference_to_blocksize = 0;
    for i in 1..blocksize {
        if difference_map.get(&i).unwrap() > difference_map.get(&(i - 1)).unwrap() {
            difference_to_blocksize = i;
        }
    }

    let encryption = oracle.encrypt(&vec![0; 10 * blocksize + difference_to_blocksize]);
    let mut occurance_map: HashMap<Vec<u8>, usize> = HashMap::new();
    for chunk in encryption.chunks(blocksize) {
        let value = occurance_map.entry(chunk.to_vec()).or_insert(0);
        *value += 1;
    }

    let zero_encryption = occurance_map
        .iter()
        .max_by(|a, b| a.1.cmp(&b.1))
        .map(|(k, _v)| k)
        .unwrap();

    let chunk_pos = encryption
        .chunks(blocksize)
        .position(|chunk| chunk == *zero_encryption)
        .unwrap();

    let prefix_length = chunk_pos * blocksize - difference_to_blocksize;

    let minimal_encryption_len = oracle.encrypt(&vec![0; difference_to_blocksize]).len();

    let block_offset = (prefix_length + difference_to_blocksize) / blocksize;

    (
        prefix_length,
        minimal_encryption_len / blocksize - block_offset,
    )
}

fn decrypt_block(
    oracle: &impl EncryptionOracle,
    blocksize: usize,
    block: usize,
    previous_block: &[u8],
    random_prefix_length: usize,
) -> Vec<u8> {
    let mut result = previous_block.to_vec();
    let mut map: HashMap<Vec<u8>, u8> = HashMap::new();

    let bytes_to_insert = (blocksize - (random_prefix_length % blocksize)) % blocksize;

    let block_offset = (random_prefix_length + bytes_to_insert) / blocksize;

    let start_offset_pos = block_offset * blocksize;
    let end_offset_pos = (block_offset + 1) * blocksize;

    let start_pos = (block + block_offset) * blocksize;
    let end_pos = (block + block_offset + 1) * blocksize;

    for byte_offset in 1..=blocksize {
        result.rotate_left(1);

        for i in 0..=255 {
            result[blocksize - 1] = i;
            let mut to_encrypt = vec![0; bytes_to_insert];
            to_encrypt.append(&mut result.clone());
            map.insert(
                oracle.encrypt(&to_encrypt)[start_offset_pos..end_offset_pos].to_vec(),
                i,
            );
        }

        let mut to_encrypt = vec![0; bytes_to_insert];
        to_encrypt.append(&mut result.clone());
        let encr = oracle.encrypt(&to_encrypt[0..blocksize + bytes_to_insert - byte_offset])
            [start_pos..end_pos]
            .to_vec();

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

    use rand::{Rng, RngCore};

    use crate::util::{base_64::Base64, generators::generate_aes_key};

    use super::*;

    #[test]
    fn s02e04() {
        let input = fs::read_to_string("data/set2/4.txt")
            .expect("Something went wrong reading the challenge file");
        let input = input.replace("\n", "");

        let oracle = ECBOracleSimple {
            secret: Base64::new_from_string(&input).unwrap().to_bytes().to_vec(),
            key: generate_aes_key(),
        };

        let dec = decrypt_ecb(&oracle);

        let dec_str = from_utf8(&dec).unwrap();

        let plain = fs::read_to_string("data/set2/4_plain.txt")
            .expect("Something went wrong reading the result file");

        assert_eq!(dec_str, &plain);
    }

    #[test]
    fn s02e06() {
        let input = fs::read_to_string("data/set2/4.txt")
            .expect("Something went wrong reading the challenge file");
        let input = input.replace("\n", "");

        let random_vec_len = rand::thread_rng().gen_range(0..32);
        let mut random_vec = vec![0; random_vec_len];
        rand::thread_rng().fill_bytes(&mut random_vec);

        let oracle = ECBOracleHard {
            secret: Base64::new_from_string(&input).unwrap().to_bytes().to_vec(),
            key: generate_aes_key(),
            random: random_vec,
        };

        let dec = decrypt_ecb(&oracle);

        let dec_str = from_utf8(&dec).unwrap();

        let plain = fs::read_to_string("data/set2/4_plain.txt")
            .expect("Something went wrong reading the result file");

        assert_eq!(dec_str, &plain);
    }
}
