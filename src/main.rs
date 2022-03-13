use core::time;

use cryptopals::{
    s04::timing_oracle::{break_timing_oracle, TimingOracle},
    util::generators::generate_aes_key,
};

fn main() {
    let oracle = TimingOracle::new(&generate_aes_key(), time::Duration::from_micros(500));

    let filename = b"filename";

    let result = break_timing_oracle(filename, &oracle, 4);

    assert!(oracle.check(filename, &result))
}
