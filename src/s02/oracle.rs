pub trait EncryptionOracle {
    fn encrypt(&self, input: &[u8]) -> Vec<u8>;
}
