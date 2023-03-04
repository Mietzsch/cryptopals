use crate::util::generators::generate_random_range;

use super::dsa::{DsaParameters, Signature};

pub fn create_random_signature(parameters: &DsaParameters) -> Signature {
    let one = rug::Integer::from(1);
    let r = generate_random_range(&one, &parameters.q);
    let s = generate_random_range(&one, &parameters.q);
    Signature { r, s }
}

pub fn create_fake_signature(parameters: &DsaParameters, y: &rug::Integer) -> Signature {
    let z = generate_random_range(&rug::Integer::from(1), &parameters.q);
    let r = y.clone().pow_mod(&z, &parameters.p).unwrap() % &parameters.q;
    let s = (&r * z.invert(&parameters.q).unwrap()) % &parameters.q;
    Signature { r, s }
}

#[cfg(test)]
mod tests {
    use crate::s06::dsa::{generate_dsa_key, DsaPublic};

    use super::*;

    #[test]
    fn s06e05_0_as_g() {
        let parameters = DsaParameters::zero_g();
        let (dsa_public, dsa_private) = generate_dsa_key(&parameters);
        let message = "Hello, world";

        let signature = dsa_private.sign(message.as_bytes());
        println!("r: {}, s: {}", signature.r, signature.s);
        assert!(!dsa_public.verify(message.as_bytes(), &signature));

        let fake_signature = create_random_signature(&parameters);
        assert!(!dsa_public.verify(message.as_bytes(), &fake_signature));
    }

    #[test]
    fn s06e05_1_as_g() {
        let correct_parameters = DsaParameters::default_parameters();
        let (dsa_public, dsa_private) = generate_dsa_key(&correct_parameters);
        let message1 = "Hello, world";

        let signature = dsa_private.sign(message1.as_bytes());
        assert!(dsa_public.verify(message1.as_bytes(), &signature));

        let fake_parameters = DsaParameters::one_g();
        let fake_signature = create_fake_signature(&fake_parameters, &dsa_public.y);
        let fake_pk = DsaPublic {
            y: dsa_public.y,
            parameters: fake_parameters,
        };

        assert!(fake_pk.verify(message1.as_bytes(), &fake_signature));

        let message2 = "Goodbye, world";
        assert!(fake_pk.verify(message2.as_bytes(), &fake_signature));
    }
}
