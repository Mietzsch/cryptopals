use num_primes::*;

fn main() {
    let numbers = [3u32.into()];

    for number in numbers {
        if Verification::is_prime(&number) {
            println!("{} is a prime number", number);
        } else {
            println!("{} is not a prime number", number);
        }
    }
}
