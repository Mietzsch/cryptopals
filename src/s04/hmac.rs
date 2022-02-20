use crate::util::xor::xor;

use super::sha1::sha1;

pub fn sha1_hmac(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut key_padded;
    if key.len() <= 64 {
        key_padded = key.to_vec();
        key_padded.append(&mut vec![0; 64 - key.len()]);
    } else {
        key_padded = sha1(key).to_vec();
        key_padded.append(&mut vec![0; 64 - 20]);
    }

    sha1(
        &[
            xor(&key_padded, &[0x5C; 64]),
            sha1(&[&xor(&key_padded, &[0x36; 64]), message].concat()).to_vec(),
        ]
        .concat(),
    )
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn sha1_hmac_kat() {
        let key1 = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();

        let data1 = "Hi There";

        let digest1 = sha1_hmac(&key1, data1.as_bytes());

        assert_eq!(
            hex::encode(&digest1),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );

        let key2 = [0xaa; 80];

        let data2 = "Test Using Larger Than Block-Size Key - Hash Key First";

        let digest2 = sha1_hmac(&key2, data2.as_bytes());

        assert_eq!(
            hex::encode(&digest2),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );

        let key3 = [0xaa; 20];

        let data3 = [0xdd; 50];

        let digest3 = sha1_hmac(&key3, &data3);

        assert_eq!(
            hex::encode(&digest3),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );

        let key4 = [0xaa; 80];

        let data4 = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";

        let digest4 = sha1_hmac(&key4, data4.as_bytes());

        assert_eq!(
            hex::encode(&digest4),
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        );
    }
}
