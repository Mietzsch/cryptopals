use rug::Integer;

use crate::s04::{hmac::sha1_hmac, sha1::sha1};

use super::dh::{generate_dh_key, get_nist_g, get_nist_p};

pub struct Server {
    salt: u8,
    n: Integer,
    g: Integer,
    k: Integer,
    v: Integer,
    a_public: Option<Integer>,
    b_private: Option<Integer>,
    u: Option<Integer>,
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
        let k = Integer::from(3);
        let v = g.clone().pow_mod(&x, &n).unwrap();
        Server {
            salt,
            n,
            g,
            k,
            v,
            a_public: None,
            b_private: None,
            u: None,
        }
    }
    pub fn send_first_server_message(&mut self) -> (u8, Integer) {
        let (b_public, b_private) = generate_dh_key(&self.n, &self.g);
        self.b_private = Some(b_private);
        (
            self.salt,
            (self.k.clone() * self.v.clone() + b_public) % self.n.clone(),
        )
    }

    pub fn compute_u(&mut self, a: &Integer) {
        let mut hash_input = a.to_digits::<u8>(rug::integer::Order::Msf);
        let b = (self.k.clone() * self.v.clone()
            + self
                .g
                .clone()
                .pow_mod(self.b_private.as_ref().unwrap(), &self.n)
                .unwrap())
            % self.n.clone();
        hash_input.append(&mut b.to_digits(rug::integer::Order::Msf));
        self.u = Some(Integer::from_digits(&hash_input, rug::integer::Order::Msf));
        self.a_public = Some(a.to_owned());
    }

    pub fn login(&self, k_in: &[u8; 20]) -> bool {
        let s = (self.a_public.as_ref().unwrap()
            * self
                .v
                .clone()
                .pow_mod(self.u.as_ref().unwrap(), &self.n)
                .unwrap())
        .pow_mod(self.b_private.as_ref().unwrap(), &self.n)
        .unwrap();
        let k = sha1(&s.to_digits(rug::integer::Order::Msf));
        sha1_hmac(&k, &vec![self.salt]) == k_in.to_owned()
    }
}

pub struct Client {
    password: Vec<u8>,
    salt: Option<u8>,
    n: Integer,
    g: Integer,
    k: Integer,
    a_private: Option<Integer>,
    b_public: Option<Integer>,
    u: Option<Integer>,
}

impl Client {
    pub fn new(password: &[u8]) -> Self {
        Client {
            password: password.to_vec(),
            salt: None,
            n: get_nist_p(),
            g: get_nist_g(),
            k: Integer::from(3),
            a_private: None,
            b_public: None,
            u: None,
        }
    }

    pub fn send_first_client_message(&mut self) -> Integer {
        let (a_public, a_private) = generate_dh_key(&self.n, &self.g);
        self.a_private = Some(a_private);
        a_public
    }

    pub fn compute_u(&mut self, b: &Integer, salt: u8) {
        let a = self
            .g
            .clone()
            .pow_mod(self.a_private.as_ref().unwrap(), &self.n)
            .unwrap();
        let mut hash_input = a.to_digits::<u8>(rug::integer::Order::Msf);
        hash_input.append(&mut b.to_digits(rug::integer::Order::Msf));
        self.u = Some(Integer::from_digits(&hash_input, rug::integer::Order::Msf));
        self.salt = Some(salt);
        self.b_public = Some(b.to_owned());
    }

    pub fn send_login_message(&self) -> [u8; 20] {
        let mut concat = vec![self.salt.unwrap()];
        concat.append(&mut self.password.to_owned());
        let x_h = sha1(&concat);
        let x = Integer::from_digits(&x_h, rug::integer::Order::Msf);
        let base = self.b_public.as_ref().unwrap() + self.n.clone() * 3u8
            - self.k.clone() * self.g.clone().pow_mod(&x, &self.n).unwrap();
        let s = base
            .pow_mod(
                &(self.a_private.as_ref().unwrap() + self.u.as_ref().unwrap() * x),
                &self.n,
            )
            .unwrap();
        let k = sha1(&s.to_digits(rug::integer::Order::Msf));
        sha1_hmac(&k, &vec![self.salt.unwrap()])
    }
}

pub struct ClientMitm {
    salt: Option<u8>,
    n: Integer,
}

impl ClientMitm {
    pub fn new() -> Self {
        ClientMitm {
            salt: None,
            n: get_nist_p(),
        }
    }

    pub fn send_first_client_message_zero(&self) -> Integer {
        Integer::from(0)
    }

    pub fn send_first_client_message_n(&self) -> Integer {
        self.n.clone()
    }

    pub fn set_salt(&mut self, salt: u8) {
        self.salt = Some(salt);
    }

    pub fn send_login_message(&self) -> [u8; 20] {
        let s = Integer::from(0);
        let k = sha1(&s.to_digits(rug::integer::Order::Msf));
        sha1_hmac(&k, &vec![self.salt.unwrap()])
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn s05e04() {
        let pw = "123";

        let mut server = Server::new(pw.as_bytes());
        let mut client = Client::new(pw.as_bytes());

        let a_public = client.send_first_client_message();
        let (salt, b_public) = server.send_first_server_message();

        client.compute_u(&b_public, salt);
        server.compute_u(&a_public);

        let client_login = client.send_login_message();
        let result = server.login(&client_login);

        assert_eq!(result, true);
    }

    #[test]
    fn s05e05() {
        let pw = "123";

        let mut server = Server::new(pw.as_bytes());
        let mut client_mal = ClientMitm::new();

        let a_public_zero = client_mal.send_first_client_message_zero();
        let (salt_zero, _b_public_zero) = server.send_first_server_message();

        client_mal.set_salt(salt_zero);
        server.compute_u(&a_public_zero);

        let client_login_zero = client_mal.send_login_message();
        let result_zero = server.login(&client_login_zero);

        assert_eq!(result_zero, true);

        let a_public_zero = client_mal.send_first_client_message_zero();
        let (salt_zero, _b_public_zero) = server.send_first_server_message();

        client_mal.set_salt(salt_zero);
        server.compute_u(&a_public_zero);

        let client_login_zero = client_mal.send_login_message();
        let result_zero = server.login(&client_login_zero);

        assert_eq!(result_zero, true);

        let a_public_n = client_mal.send_first_client_message_n();
        let (salt_n, _b_public_n) = server.send_first_server_message();

        client_mal.set_salt(salt_n);
        server.compute_u(&a_public_n);

        let client_login_n = client_mal.send_login_message();
        let result_n = server.login(&client_login_n);

        assert_eq!(result_n, true);
    }
}
