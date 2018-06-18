extern crate hmac;
extern crate hkdf;
extern crate rand;
extern crate x25519_dalek;
extern crate ed25519_dalek;
extern crate sha2;
extern crate openssl;
extern crate clear_on_drop;

pub mod olm_shared_secret;
pub mod rc_keys;
pub mod authenticated_encryption;