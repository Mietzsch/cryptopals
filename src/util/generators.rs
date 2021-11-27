pub fn generate_aes_key() -> Vec<u8> {
    let mut v: Vec<u8> = vec![0; 16];

    for x in v.iter_mut() {
        *x = rand::random()
    }
    v
}
