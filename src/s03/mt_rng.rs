use std::{cmp::Ordering, convert::TryInto};

use crate::util::bits::{get_bit, to_u64};

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
        MTRng { mt, index: MT_N }
    }
    pub fn extract_number(&mut self) -> u32 {
        match self.index.cmp(&MT_N) {
            Ordering::Less => {}
            Ordering::Greater => {
                panic!("MTRng was never seeded!")
            }
            Ordering::Equal => self.twist(),
        }

        let y = temper(self.mt[self.index]);

        self.index += 1;
        as_w_bits(y) as u32
    }
    fn twist(&mut self) {
        for i in 0..MT_N {
            let x = (self.mt[i] & MT_UPPER_MASK) + (self.mt[(i + 1) % MT_N] & MT_LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= MT_A;
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

fn temper(x: u64) -> u64 {
    let mut y = x ^ ((x >> MT_U) & MT_D);
    y = y ^ ((y << MT_S) & MT_B);
    y = y ^ ((y << MT_T) & MT_C);
    y = y ^ (y >> MT_L);
    y
}

fn untemper_right(x: u64, rightshift: usize, and_number: u64) -> u64 {
    let mut res = 0;
    let rightshift: u32 = rightshift.try_into().unwrap();

    for i in (0..64).rev() {
        let i_as_usize = i.try_into().unwrap();
        if i >= 64 - rightshift {
            res += to_u64(get_bit(x, i_as_usize), i_as_usize)
        } else {
            res = res
                + to_u64(
                    get_bit(x, i_as_usize)
                        ^ (get_bit(res, (i + rightshift).try_into().unwrap())
                            & get_bit(and_number, i_as_usize)),
                    i_as_usize,
                )
        }
    }
    res
}

fn untemper_left(x: u64, leftshift: usize, and_number: u64) -> u64 {
    let mut res = 0;
    let leftshift: u32 = leftshift.try_into().unwrap();

    for i in 0..64 {
        let i_as_usize = i.try_into().unwrap();
        if i < leftshift {
            res += to_u64(get_bit(x, i_as_usize), i_as_usize)
        } else {
            res = res
                + to_u64(
                    get_bit(x, i_as_usize)
                        ^ (get_bit(res, (i - leftshift).try_into().unwrap())
                            & get_bit(and_number, i_as_usize)),
                    i_as_usize,
                )
        }
    }
    res
}

fn untemper(y: u64) -> u64 {
    let mut x = untemper_right(y, MT_L, u64::MAX);
    x = untemper_left(x, MT_T, MT_C);
    x = untemper_left(x, MT_S, MT_B);
    x = untemper_right(x, MT_U, MT_D);
    x
}

pub fn clone_mt_rng(original: &mut MTRng) -> Option<MTRng> {
    for _ in 0..MT_N {
        let mut mt = [0; MT_N];
        for item in mt.iter_mut().take(MT_N) {
            *item = untemper(original.extract_number().into());
        }
        let mut potential_clone = MTRng { mt, index: MT_N };
        if original.extract_number() == potential_clone.extract_number() {
            return Some(potential_clone);
        }
    }
    None
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

    #[test]
    fn reverse_temper() {
        let input = 23834434;
        let tempered_easy = temper(input);
        assert_eq!(untemper(tempered_easy), input);
    }

    #[test]
    fn s03e07() {
        let mut rng = MTRng::new(2389);
        let offset = rng.extract_number() % 624;
        for _ in 0..offset {
            let _ = rng.extract_number();
        }

        let mut copy = clone_mt_rng(&mut rng).unwrap();

        for _ in 0..MT_N {
            assert_eq!(rng.extract_number(), copy.extract_number());
        }
    }
}
