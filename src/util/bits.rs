use std::convert::TryInto;

pub fn get_bit(x: u64, index: usize) -> bool {
    let mask: u64 = 2_u64.pow(index.try_into().unwrap());
    let masked_x = x & mask;
    let bit = masked_x >> index;
    if bit == 1 {
        true
    } else {
        false
    }
}

pub fn to_u64(bit: bool, index: usize) -> u64 {
    if bit {
        2_u64.pow(index.try_into().unwrap())
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits() {
        let test_number = 167;
        assert_eq!(get_bit(test_number, 7), true);
        assert_eq!(get_bit(test_number, 6), false);
        assert_eq!(get_bit(test_number, 5), true);
        assert_eq!(get_bit(test_number, 4), false);
        assert_eq!(get_bit(test_number, 3), false);
        assert_eq!(get_bit(test_number, 2), true);
        assert_eq!(get_bit(test_number, 1), true);
        assert_eq!(get_bit(test_number, 0), true);
    }

    #[test]
    fn test_to_bit() {
        assert_eq!(to_u64(true, 7), 128);
        assert_eq!(to_u64(true, 2), 4);
        assert_eq!(to_u64(false, 7), 0);
    }
}
