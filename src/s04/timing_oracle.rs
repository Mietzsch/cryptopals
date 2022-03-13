use std::{
    thread,
    time::{Duration, SystemTime},
};

use super::hmac::sha1_hmac;

pub struct TimingOracle {
    key: Vec<u8>,
    timeout: Duration,
}

impl TimingOracle {
    pub fn new(key: &[u8], timeout: Duration) -> TimingOracle {
        TimingOracle {
            key: key.to_vec(),
            timeout,
        }
    }

    pub fn check(&self, file: &[u8], signature: &[u8]) -> bool {
        let hmac = sha1_hmac(&self.key, file);
        for i in 0..hmac.len() {
            if signature[i] != hmac[i] {
                return false;
            }
            thread::sleep(self.timeout);
        }
        return true;
    }
}

// works down to 1ms timeouts. What should be an improvement is to take all times per bytes first and then see if the longest is longer than the threshold.
pub fn break_timing_oracle(file: &[u8], oracle: &TimingOracle, samples: usize) -> [u8; 20] {
    let mut result = [0; 20];

    let mut baseline = 0.0;

    let mut times = [0.0; 20];

    //for i in (0..result.len()).progress_with(create_progress_bar(result.len() as u64)) {
    let mut i = 0;
    while i < result.len() {
        let mut best_byte = 0;
        let mut found_something = false;
        for j in 0..=255 {
            result[i] = j;
            let timing_result = time_result(file, &result, oracle, samples);
            if timing_result.0 {
                println!("Found matching signature!");
                return result;
            } else {
                if i != 0 {
                    if timing_result.1 > times[i - 1] + baseline / 1.25 {
                        // println!(
                        //     "New time: {}, to beat: {}",
                        //     timing_result.1,
                        //     best_time + baseline / 2.0
                        // );
                        times[i] = timing_result.1;
                        best_byte = j;
                        found_something = true;
                        break;
                    }
                } else {
                    if timing_result.1 > times[i] + baseline / 1.25 {
                        // println!(
                        //     "New time: {}, to beat: {}",
                        //     timing_result.1,
                        //     best_time + baseline / 2.0
                        // );
                        times[i] = timing_result.1;
                        best_byte = j;
                        found_something = true;
                    }
                }
            }
        }
        if i == 0 {
            baseline = times[i];
            println!("Set baseline to {}", baseline);
        }
        if found_something {
            if i == 19 && !time_result(file, &result, oracle, samples).0 {
                i = i - 1;
                println!("Go back to pos {}", i);
            } else {
                println!(
                    "Found byte {} in pos {}, new longest time: {}",
                    best_byte, i, times[i]
                );
                result[i] = best_byte;
                i = i + 1;
            }
        } else {
            i = i - 1;
            println!("Go back to pos {}", i);
        }
    }

    return result;
}

fn time_result(
    file: &[u8],
    signature: &[u8],
    oracle: &TimingOracle,
    samples: usize,
) -> (bool, f64) {
    let mut res = 0.0;
    let mut res_bool = false;
    for _ in 0..samples {
        let sys_time = SystemTime::now();

        res_bool = oracle.check(file, signature);

        let new_sys_time = SystemTime::now();
        let difference = new_sys_time
            .duration_since(sys_time)
            .expect("Clock may have gone backwards");
        res += difference.as_micros() as f64;
    }

    (res_bool, res / samples as f64)
}

#[cfg(test)]
mod tests {

    use core::time;

    use crate::util::generators::generate_aes_key;

    use super::*;

    #[test]
    #[ignore]
    fn s04e07() {
        let oracle = TimingOracle::new(&generate_aes_key(), time::Duration::from_millis(10));

        let filename = b"filename";

        let result = break_timing_oracle(filename, &oracle, 1);

        assert!(oracle.check(filename, &result))
    }
    #[test]
    #[ignore]
    fn s04e08() {
        let oracle = TimingOracle::new(&generate_aes_key(), time::Duration::from_micros(1000));

        let filename = b"filename";

        let result = break_timing_oracle(filename, &oracle, 4);

        assert!(oracle.check(filename, &result))
    }
}
