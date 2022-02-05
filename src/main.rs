use cryptopals::s03::mt_rng::{clone_mt_rng, MTRng};

fn main() {
    let mut rng = MTRng::new(2389);
    //let _ = rng.extract_number();
    let mut copy = clone_mt_rng(&mut rng).unwrap();
    println!(
        "Next values: {}, {}",
        rng.extract_number(),
        copy.extract_number()
    );
}
