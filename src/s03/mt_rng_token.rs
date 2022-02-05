use std::{convert::TryInto, time::SystemTime};

use super::mt_rng::MTRng;

pub fn create_reset_token() -> u32 {
    let sys_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rng = MTRng::new(sys_time.try_into().unwrap());
    rng.extract_number()
}

pub fn check_for_reset_token(token: u32) -> Option<u32> {
    let current_time: u32 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();
    for key in (0..current_time).rev() {
        let mut rng = MTRng::new(key);
        if token == rng.extract_number() {
            return Some(key);
        }
    }
    None
}

#[cfg(test)]
mod tests {

    use std::{thread::sleep, time::Duration};

    use super::*;

    #[test]
    fn s03e08_time_token() {
        let token = create_reset_token();
        sleep(Duration::new(2, 0));
        assert_ne!(None, check_for_reset_token(token));
    }
}
