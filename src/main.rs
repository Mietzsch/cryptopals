use std::time::SystemTime;

use cryptopals::s03::mt_rng::{guess_rng_seed, MTRng};

fn main() {
    let unix_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let seed_time = unix_time + (rand::random::<u32>() % 600);
    let mut rng = MTRng::new(seed_time);
    let out_time = seed_time + (rand::random::<u32>() % 600);
    let random = rng.extract_number();
    let guess = guess_rng_seed(random, 1300, out_time).expect("No seed found");
    if seed_time == guess {
        println!("Found seed: {}", seed_time);
    }
}
