use rug::Integer;

pub fn generate_aes_key() -> Vec<u8> {
    let mut v: Vec<u8> = vec![0; 16];

    for x in v.iter_mut() {
        *x = rand::random()
    }
    v
}

pub fn generate_random_bigint(bits: usize) -> Integer {
    let remaining_bits = bits % 8;
    let bytes_needed = bits / 8 + (remaining_bits != 0) as usize;
    let mut random_vec = vec![0u8; bytes_needed];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_vec);
    let mut result = Integer::from_digits(&random_vec, rug::integer::Order::Lsf);
    for index in (bytes_needed - 1) * 8 + remaining_bits..bytes_needed * 8 {
        result.set_bit(index.try_into().unwrap(), false);
    }
    result
}

pub fn generate_prime(bits: usize) -> Integer {
    loop {
        let candidate = generate_random_bigint(bits);
        if candidate.is_probably_prime(30) != rug::integer::IsPrime::No {
            return candidate;
        }
    }
}

pub fn generate_random_range(lower: &Integer, upper: &Integer) -> Integer {
    let bits = upper.significant_bits();
    loop {
        let candidate = generate_random_bigint(bits.try_into().unwrap());
        if &candidate >= lower && &candidate < upper {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_random() {
        let size = 3;

        let random = generate_random_bigint(size);
        assert!(random < 8);
    }

    #[test]
    fn test_random_range() {
        let lower = Integer::from(3);
        let upper = Integer::from(17);

        let random = generate_random_range(&lower, &upper);
        assert!(lower <= random && random < upper);
    }
}
