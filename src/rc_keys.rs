use sha2::Sha256;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use olm_shared_secret::OlmSharedSecret;
use x25519_dalek::diffie_hellman;
use clear_on_drop::clear::Clear;

// https://git.matrix.org/git/olm/about/docs/olm.rst
// Section: The Olm Algortihm, Initial setup
// Root key and chain key

pub struct RootChainKeys { pub shared_secret: Vec<u8> }

impl Drop for RootChainKeys {
    fn drop(&mut self) {
        self.shared_secret.clear();
    }
}

// This type alias seems to be needed for HMAC
type HmacSha256 = Hmac<Sha256>;

impl RootChainKeys {

    //  R0 ∥ C0, 0  = HKDF(0,  S,  "OLM_ROOT",  64)
    // Here || denotes splitting
    pub fn compute_initial_keys(&self) -> (Vec<u8>, Vec<u8>) {
        // These values don't need to be allocated here, but keeping it for now, for easier
        // reference to docs
        assert_eq!(self.shared_secret.len(), 96); //32*3
        let salt = [0u8; 1];
        let info = "OLM_ROOT";
        let length = 64;
        // ikm will be the shared secret s

        let hkdf_extract = Hkdf::<Sha256>::extract(&salt, &self.shared_secret);
        // Has to be mut for split_off()
        let mut root_key = hkdf_extract.expand(info.as_bytes(), length);
        // Split at 32, to split in the middle
        // So both the root key and chain zero key are 256 bit in length
        let chain_key_zero = root_key.split_off(32);
        assert_eq!(root_key.len(), chain_key_zero.len());

        (root_key, chain_key_zero)

    }

    // previous_root_key = Ri − 1
    // previous_ratchet_key = Ti − 1
    // current_ratchet_key = Ti
    // Output = Ri, Ci,0
    pub fn advance_root_key(&self, previous_root_key: &[u8], previous_ratchet_key: &[u8; 32],
        current_ratchet_key: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {

        // x25519_dalek needs both ECDH inputs  be exactly 32 in length
        // https://docs.rs/x25519-dalek/0.1.0/x25519_dalek/fn.diffie_hellman.html
        // Check for this

        let ratchets_shared = diffie_hellman(
            previous_ratchet_key,
            current_ratchet_key
        );

        let info = "OLM_RATCHET";
        let length = 64;

        let hkdf_extract = Hkdf::<Sha256>::extract(
            previous_root_key,
            &ratchets_shared
        );

        let mut advanced_root_key = hkdf_extract.expand(info.as_bytes(), length);
        let chain_key_i_zero = advanced_root_key.split_off(32);


        (advanced_root_key, chain_key_i_zero)

    }

    // previous_chain_key = Ci, j − 1
    // Returns Ci,j
    pub fn advance_chain_key(&self, previous_chain_key: &[u8]) -> Vec<u8> {

        let mut mac_chain_key = HmacSha256::new_varkey(previous_chain_key).expect("Error on HMACing when advaning chain key");

        mac_chain_key.input("\x02".as_bytes());

        let advanced_chain_key = mac_chain_key.result();

        advanced_chain_key.code().to_vec()

    }

    // current_chain_key = Ci,j
    // Returns Mi,j
    pub fn create_message_key(&self, current_chain_key: &[u8]) -> Vec<u8> {

        let mut mac_chain_key = HmacSha256::new_varkey(current_chain_key).expect("Error on HMACing when creating message key");

        mac_chain_key.input("\x01".as_bytes());

        let message_key = mac_chain_key.result();

        message_key.code().to_vec()

    }
}

#[cfg(test)]
mod test {
    use rc_keys::RootChainKeys;

    #[test]
    #[should_panic]
    fn short_invalid_length_shared_secret() {
        let init_root_setup = RootChainKeys { shared_secret: vec![0x01; 20] };
        init_root_setup.compute_initial_keys();
    }

    #[test]
    #[should_panic]
    fn long_invalid_length_shared_secret() {
        let init_root_setup = RootChainKeys { shared_secret: vec![0x01; 120] };
        init_root_setup.compute_initial_keys();
    }

    #[test]
    fn root_chain_32_length() {
        let init_root_setup = RootChainKeys { shared_secret: vec![0x01; 96] };
        let (rk, ck) = init_root_setup.compute_initial_keys();
        assert_eq!(rk.len(), 32);
        assert_eq!(ck.len(), 32);
    }
}
