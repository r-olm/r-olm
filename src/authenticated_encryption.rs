use hkdf::Hkdf;
use sha2::Sha256;
use openssl::{symm, error::ErrorStack};
use hmac::{Hmac, Mac};
use clear_on_drop::clear::Clear;

// https://git.matrix.org/git/olm/about/docs/olm.rst
// Section: The Olm Algortihm, Olm Authenticated Encryption
// Version 1

const MAC_LENGTH: usize = 8;
type HmacSha256 = Hmac<Sha256>;

pub struct EncryptionKeys {
    aes_key: Vec<u8>,
    hmac_key: Vec<u8>,
    aes_iv: Vec<u8>
}

impl Drop for EncryptionKeys {
    fn drop(&mut self) {
        Clear::clear(&mut self.aes_key);
        Clear::clear(&mut self.hmac_key);
        Clear::clear(&mut self.aes_iv);
    }
}

impl EncryptionKeys {

    // AES_KEY(i, j) || HMAC_KEY(i, j) || AES_IV(i, j) = HKDF(0, M9i, j), "OLM_KEYS", 80)
    pub fn compute_keys(msg_key: &[u8]) -> Self {
        let salt = [0u8; 64];
        let info = "OLM_KEYS";
        let length = 80;
        // ikm will be the shared the message key M(i, j)
        let hkdf_extract = Hkdf::<Sha256>::extract(&salt, &msg_key);
        
        //128 bit AES_IV
        //256 bit AES_KEY
        //256 bit HMAC_KEY
        let mut aes_key = hkdf_extract.expand(info.as_bytes(), length);
        assert_eq!(aes_key.len(), 80);
        
        let mut hmac_key = aes_key.split_off(32);
        let aes_iv = hmac_key.split_off(32);
        
        assert_eq!(aes_key.len(), 32);
        assert_eq!(hmac_key.len(), 32);
        assert_eq!(aes_iv.len(), 16);

        Self {
            aes_key,
            hmac_key,
            aes_iv
        }
    }

    // encrypts plain-text with AES-256, using the key AES_KEY(i, j) and the IV AES_IV(i, j) to give the cipher-text, X(i, j)
    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>,ErrorStack> {
        let cipher = symm::Cipher::aes_256_cbc();
        symm::encrypt(cipher, &self.aes_key, Some(&self.aes_iv), msg)
    }

    // decrypts cipher_text X(i, j)
    pub fn decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>,ErrorStack> {
        let cipher = symm::Cipher::aes_256_cbc();
        symm::decrypt(cipher, &self.aes_key, Some(&self.aes_iv), cipher_text)
    }

    // produces a 8 byte MAC from the input with the HMAC_KEY(i, j). The input shpuld be the entire message(including the Version Bytes and all Payload Bytes)
    pub fn authenticate(&self, input: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_varkey(&self.hmac_key).expect("error while creating MAC instance from key");
        mac.input(input);
        let mut code = Vec::from(mac.result().code().as_ref());
        code.truncate(MAC_LENGTH);
        code
    }

    // verfies the MAC
    pub fn verify_mac(&self, input: &[u8], code_bytes: &[u8]) -> bool {
        let new_code = self.authenticate(input);
        new_code == code_bytes
    }
}

#[cfg(test)]
mod test {
    use super::EncryptionKeys;

    fn get_encrption_keys() -> EncryptionKeys {
        EncryptionKeys::compute_keys(&[0x01; 32])
    }

    #[test]
    fn check_encryption() {
        let enc_keys = get_encrption_keys();
        let msg = b"input msg";
        let cipher_text = enc_keys.encrypt(msg).expect("error while encrypting with OpenSSL");
        let decrypted_msg = enc_keys.decrypt(&cipher_text).unwrap();
        assert_eq!(msg, &decrypted_msg[..])

    }

    #[test]
    fn check_hmac() {
        let enc_keys = get_encrption_keys();
        let input = b"input msg";
        let code = enc_keys.authenticate(input);
        assert!(enc_keys.verify_mac(input, &code));
    }
}
