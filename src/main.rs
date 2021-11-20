use cryptopals::s02::padding::pkcs7_padding;

fn main() {
    let input = String::from("YELLOW SUBMARINE");

    let res = pkcs7_padding(input.as_bytes(), 20);

    println!("{}", hex::encode(res));
}
