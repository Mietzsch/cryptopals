use cryptopals::util::xor;

fn main() {
    let string1 = String::from("this is a test");
    let string2 = String::from("wokka wokka!!!");

    let hamming = xor::hamming(string1.as_bytes(), string2.as_bytes());

    println!("hamming difference: {}", hamming);
}
