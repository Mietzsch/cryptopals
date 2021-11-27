use cryptopals::s02::encryption_oracle::detect_ecb_cbc;

fn main() {
    for _ in 0..10 {
        let prediction = detect_ecb_cbc();
        println!("Predicted: {}, was {}", prediction.0, prediction.1);
    }
}
