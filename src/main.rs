use cryptopals::{s02::admin::AdminOracleCBC, util::generators::generate_aes_key};

fn main() {
    let prefix = b"comment1=cooking MCs;userdata=";
    let postfix = b";comment2= like a pound of bacon";

    let admin_oracle = AdminOracleCBC::new(&generate_aes_key(), prefix, postfix);

    let pad = [0; 2];
    let zero_block = [0; 16];
    let admin = b"\0\0\0\0\0\0admin\0true";

    let mut input = Vec::new();
    input.append(&mut pad.to_vec());
    input.append(&mut zero_block.to_vec());
    input.append(&mut admin.to_vec());

    let mut encr = admin_oracle.encrypt(&input);

    encr.1[prefix.len() + pad.len() + 5] ^= b';';
    encr.1[prefix.len() + pad.len() + 11] ^= b'=';

    let success = admin_oracle.is_admin(&encr.0, &encr.1);

    println!("Success: {}", success);
}
