use std::cmp::Ordering;

const MT_W: usize = 32;
const MT_N: usize = 624;
const MT_M: usize = 397;
const MT_R: usize = 31;
const MT_A: u64 = 0x9908B0DF;
const MT_U: usize = 11;
const MT_D: u64 = 0xFFFFFFFF;
const MT_S: usize = 7;
const MT_B: u64 = 0x9D2C5680;
const MT_T: usize = 15;
const MT_C: u64 = 0xEFC60000;
const MT_L: usize = 18;
const MT_F: u64 = 1812433253;
const MT_LOWER_MASK: u64 = (1 << MT_R) - 1;
const MT_UPPER_MASK: u64 = !MT_LOWER_MASK & 0xFFFFFFFF;

pub struct MTRng {
    mt: [u64; MT_N],
    index: usize,
}

impl MTRng {
    pub fn new(seed: u32) -> MTRng {
        let mut mt = [0; MT_N];
        mt[0] = seed as u64;
        for i in 1..MT_N {
            mt[i] = as_w_bits(MT_F * (mt[i - 1] ^ (mt[i - 1] >> (MT_W - 2))) + i as u64);
        }
        MTRng {
            mt: mt,
            index: MT_N,
        }
    }
    pub fn extract_number(&mut self) -> u32 {
        match self.index.cmp(&MT_N) {
            Ordering::Less => {}
            Ordering::Greater => {
                panic!("MTRng was never seeded!")
            }
            Ordering::Equal => self.twist(),
        }

        let mut y = self.mt[self.index];
        y = y ^ ((y >> MT_U) & MT_D);
        y = y ^ ((y << MT_S) & MT_B);
        y = y ^ ((y << MT_T) & MT_C);
        y = y ^ (y >> MT_L);

        self.index = self.index + 1;
        as_w_bits(y) as u32
    }
    fn twist(&mut self) {
        for i in 0..MT_N {
            let x = (self.mt[i] & MT_UPPER_MASK) + (self.mt[(i + 1) % MT_N] & MT_LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a = x_a ^ MT_A;
            }
            self.mt[i] = self.mt[(i + MT_M) % MT_N] ^ x_a;
        }
        self.index = 0;
    }
}

fn as_w_bits(number: u64) -> u64 {
    if MT_W == 32 {
        number & 0xFFFFFFFF
    } else {
        number
    }
}

pub fn guess_rng_seed(output: u32, max_time: u32, out_time: u32) -> Option<u32> {
    let first_seed = out_time - max_time;
    for potential_seed in first_seed..out_time {
        let mut rng = MTRng::new(potential_seed);
        if rng.extract_number() == output {
            return Some(potential_seed);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::{fs, time::SystemTime};

    use super::*;

    #[test]
    fn s03e05() {
        let seed = 1131464071;
        let mut mt_rng = MTRng::new(seed);

        let input = fs::read_to_string("data/set3/5.txt")
            .expect("Something went wrong reading the KAT file");

        for line in input.lines() {
            let kat_number = line.parse::<u32>().unwrap();
            assert_eq!(kat_number, mt_rng.extract_number());
        }
    }

    #[test]
    fn s03e06() {
        let unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let seed_time = unix_time + (rand::random::<u32>() % 600);
        let mut rng = MTRng::new(seed_time);
        let out_time = seed_time + (rand::random::<u32>() % 600);
        let random = rng.extract_number();
        let guess = guess_rng_seed(random, 1300, out_time).expect("No seed found");
        assert_eq!(guess, seed_time);
    }
}
