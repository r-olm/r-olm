use x25519_dalek::diffie_hellman;
use clear_on_drop::clear::Clear;

// https://git.matrix.org/git/olm/about/docs/olm.rst
// Section: The Olm Algortihm, Initial setup
// Genrating shared secret S
pub struct OlmSharedSecret {
    pub identity_key_alice: [u8; 32],
    pub identity_key_bob: [u8; 32],
    pub one_time_key_alice: [u8; 32],
    pub one_time_key_bob: [u8; 32]
}


impl Drop for OlmSharedSecret {
    fn drop(&mut self) {
        self.identity_key_alice.clear();
        self.identity_key_bob.clear();
        self.one_time_key_alice.clear();
        self.one_time_key_bob.clear()
    }
}


impl OlmSharedSecret {
    /// S  = ECDH(IA,  EB) ∥ ECDH(EA,  IB) ∥ ECDH(EA,  EB)
    /// Here || denotes concantenation
    pub fn compute(&self) -> Vec<u8> {

        // Since we specify the length of the array in the struct, we don't need
        // to check the sizes of the struct fields

        // Holding final shared secret. One of the other vectors can be used for this,
        // but to begin with, just leaving this for reference to the docs
        let mut shared_S = Vec::new();

        // ECDH(IA,  EB)
        let ecdh_alice_id_bob_pub = diffie_hellman(
            &self.identity_key_alice,
            &self.one_time_key_bob
        );
        // ECDH(EA,  IB)
        let ecdh_bob_id_alice_pub = diffie_hellman(
            &self.one_time_key_alice,
            &self.identity_key_bob
        );
        // ECDH(EA,  EB)
        let ecdh_alice_pub_bob_pub = diffie_hellman(
            &self.one_time_key_alice,
            &self.one_time_key_bob,
        );

        shared_S.extend_from_slice(&ecdh_alice_id_bob_pub);
        shared_S.extend_from_slice(&ecdh_bob_id_alice_pub);
        shared_S.extend_from_slice(&ecdh_alice_pub_bob_pub);

        // Length of this will be 32*3
        // https://docs.rs/x25519-dalek/0.1.0/x25519_dalek/fn.diffie_hellman.html
        shared_S
    }
}

#[cfg(test)]
mod test {
    use olm_shared_secret::OlmSharedSecret;
    use x25519_dalek::generate_secret;
    use x25519_dalek::generate_public;
    use rand::OsRng;


    #[test]
    fn init_allowed_length_struct() {

        let mut csprng = OsRng::new().unwrap();

        let alice_secret = generate_secret(&mut csprng);
        let bob_secret = generate_secret(&mut csprng);

        let short_id_key = OlmSharedSecret {
            identity_key_alice: generate_public(&alice_secret).to_bytes(),
            identity_key_bob: generate_public(&bob_secret).to_bytes(),
            one_time_key_alice: generate_secret(&mut csprng),
            one_time_key_bob: generate_secret(&mut csprng)
        };
    }
}
