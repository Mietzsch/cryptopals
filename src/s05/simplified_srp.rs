use rug::Integer;

use super::dh::{generate_dh_key, get_nist_g, get_nist_p};
use crate::{
    s04::{hmac::sha1_hmac, sha1::sha1},
    util::progress_bar::create_progress_bar,
};

pub struct Server {
    salt: u8,
    n: Integer,
    g: Integer,
    v: Integer,
    b_private: Option<Integer>,
    u: Option<u32>,
}

impl Server {
    pub fn new(password: &[u8]) -> Self {
        let salt: u8 = rand::random();
        let mut concat = vec![salt];
        concat.append(&mut password.to_owned());
        let x_h = sha1(&concat);
        let x = Integer::from_digits(&x_h, rug::integer::Order::Msf);
        let g = get_nist_g();
        let n = get_nist_p();
        let v = g.clone().pow_mod(&x, &n).unwrap();
        Server {
            salt,
            n,
            g,
            v,
            b_private: None,
            u: None,
        }
    }
    pub fn send_challenge(&mut self) -> (u8, Integer, u32) {
        let (b_public, b_private) = generate_dh_key(&self.n, &self.g);
        self.b_private = Some(b_private);
        let u: u32 = rand::random();
        self.u = Some(u);
        (self.salt, b_public, u)
    }
    pub fn login(&self, a_public: Integer, challenge: [u8; 20]) -> bool {
        let base = a_public
            * self
                .v
                .clone()
                .pow_mod(&Integer::from(self.u.unwrap()), &self.n)
                .unwrap();
        let s = base
            .pow_mod(self.b_private.as_ref().unwrap(), &self.n)
            .unwrap();
        let k = sha1(&s.to_digits(rug::integer::Order::Msf));
        let response = sha1_hmac(&k, &[self.salt]);
        challenge == response
    }
}

pub struct Client {
    password: Vec<u8>,
    salt: Option<u8>,
    n: Integer,
    g: Integer,
    a_private: Option<Integer>,
    b_public: Option<Integer>,
    u: Option<u32>,
}

impl Client {
    pub fn new(password: &[u8]) -> Self {
        Client {
            password: password.to_vec(),
            salt: None,
            n: get_nist_p(),
            g: get_nist_g(),
            a_private: None,
            b_public: None,
            u: None,
        }
    }

    pub fn send_login_message(
        &mut self,
        salt: u8,
        b_public: Integer,
        u: u32,
    ) -> (Integer, [u8; 20]) {
        self.salt = Some(salt);
        self.b_public = Some(b_public.clone());
        self.u = Some(u);

        let (a_public, a_private) = generate_dh_key(&self.n, &self.g);
        self.a_private = Some(a_private);

        let mut concat = vec![salt];
        concat.append(&mut self.password.to_owned());
        let x_h = sha1(&concat);
        let x = Integer::from_digits(&x_h, rug::integer::Order::Msf);

        let s = b_public
            .pow_mod(
                &(self.a_private.as_ref().unwrap() + &x * Integer::from(u)),
                &self.n,
            )
            .unwrap();
        let k = sha1(&s.to_digits(rug::integer::Order::Msf));
        (a_public, sha1_hmac(&k, &[self.salt.unwrap()]))
    }
}

pub struct MitmServer {
    salt: u8,
    n: Integer,
    g: Integer,
}

impl Default for MitmServer {
    fn default() -> Self {
        MitmServer::new()
    }
}

impl MitmServer {
    pub fn new() -> Self {
        let salt: u8 = 0u8;
        let g = get_nist_g();
        let n = get_nist_p();
        MitmServer { salt, n, g }
    }
    pub fn send_challenge(&self) -> (u8, Integer, u32) {
        (self.salt, self.g.clone(), 1u32)
    }
    pub fn dict_attack(&self, a_public: Integer, challenge: [u8; 20]) -> Vec<u8> {
        let len = 1;
        let mut pw = vec![0u8; len];
        let mut overflow = false;
        let mut i = 0;
        let pb = create_progress_bar(((len - 1) * 256).try_into().unwrap());
        while !overflow {
            if self.check_pw(&a_public, &challenge, &pw) {
                return pw;
            }
            while i < len {
                if pw[i] == 255 {
                    pw[i] = 0;
                    i += 1;
                    pb.inc(1);
                } else {
                    pw[i] += 1;
                    break;
                }
            }
            if i == len {
                overflow = true;
            } else {
                i = 0;
            }
        }
        vec![0u8; len]
    }
    fn check_pw(&self, a_public: &Integer, challenge: &[u8; 20], pw: &[u8]) -> bool {
        let mut concat = vec![self.salt];
        concat.append(&mut pw.to_owned());
        let x_h = sha1(&concat);
        let x = Integer::from_digits(&x_h, rug::integer::Order::Msf);

        let s = (a_public * self.g.clone().pow_mod(&x, &self.n).unwrap()) % &self.n;
        let k = sha1(&s.to_digits(rug::integer::Order::Msf));
        let response = sha1_hmac(&k, &[self.salt]);
        *challenge == response
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn s05e06_good() {
        let pw = "123";

        let mut server = Server::new(pw.as_bytes());
        let mut client = Client::new(pw.as_bytes());

        let (salt, b_public, u) = server.send_challenge();
        let (a_public, challenge) = client.send_login_message(salt, b_public, u);

        let result = server.login(a_public, challenge);

        assert!(result);
    }
    #[test]
    fn s05e06_attack() {
        let pw = "1";

        let mitm_server = MitmServer::new();
        let mut client = Client::new(pw.as_bytes());

        let (salt, b_public, u) = mitm_server.send_challenge();
        let (a_public, challenge) = client.send_login_message(salt, b_public, u);

        let result = mitm_server.dict_attack(a_public, challenge);

        assert_eq!(result, pw.as_bytes());
    }
}
