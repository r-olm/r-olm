use sha2::Sha256;
use hkdf::Hkdf;
use olm_shared_secret::OlmSharedSecret;
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

impl RootChainKeys {
    //  R0 ∥ C0, 0  = HKDF(0,  S,  "OLM_ROOT",  64)
    // Here || denotes splitting
    // Should it be split in half?
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
        // Assuming it should be split in half
        let chain_key_zero = root_key.split_off(31);
        assert_eq!(root_key.len(), chain_key_zero.len());

        (root_key, chain_key_zero)

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
        let init_root_setup = RootChainKeys { shared_secret: vec![0x01; 60] };
        init_root_setup.compute_initial_keys();
    }
}
