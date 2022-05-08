use cryptopals::s05::simplified_srp::{Client, MitmServer};

fn main() {
    let pw = "12";

    let mitm_server = MitmServer::new();
    let mut client = Client::new(pw.as_bytes());

    let (salt, b_public, u) = mitm_server.send_challenge();
    let (a_public, challenge) = client.send_login_message(salt, b_public, u);

    let result = mitm_server.dict_attack(a_public, challenge);

    assert_eq!(result, pw.as_bytes());
}
