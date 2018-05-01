extern crate rustc_serialize;
extern crate openssl;

use rustc_serialize::{
    hex::FromHex,
    base64::{
        self,
        ToBase64
    }
};
use openssl::symm::{encrypt, Cipher};
use std::process::{
    Command,
    Stdio
};

#[test]
fn check_for_padding() {
    let _ = Command::new("pip3")
                .args(&["install", "--user", "cryptography"])
                .output();
    
    let py_script = "
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode

def encrypt(text, key, iv):
  be = default_backend()

  iv = bytes.fromhex(iv)
  key = bytes.fromhex(key)

  cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=be)
  padder = padding.PKCS7(algorithms.AES.block_size).padder()
  encryptor = cipher.encryptor()
  s = padder.update(str.encode(text)) + padder.finalize()
  res = encryptor.update(s) + encryptor.finalize()
  return b64encode(res)

key = '5EBE2294ECD0E0F08EAB7690D2A6EE6926AE5CC854E36B6BDFCA366848DEA6BB'
iv  = 'E8C80B4B831FBB64B0D5C6C8499E541A'
print(encrypt('hello', key, iv).decode('utf-8'))
";

    let py_script = Command::new("echo")
                .arg(py_script)
                .stdout(Stdio::piped())
                .spawn()
                .expect("Could not echo the script")
                .stdout
                .expect("failed to get the stdout for py script");

    let py_script = Command::new("python3")
                        .stdin(Stdio::from(py_script))
                        .output()
                        .expect("Could not execute the pyscript");
    
    let ciphertext_py = String::from_utf8(py_script.stdout).expect("could not get the stdout from py script");
    let ciphertext_py = ciphertext_py.trim();
    
    let cipher = Cipher::aes_256_cbc();
    let key = str::from_hex("5EBE2294ECD0E0F08EAB7690D2A6EE6926AE5CC854E36B6BDFCA366848DEA6BB").expect("Can't get key from hex");
    let iv = str::from_hex("E8C80B4B831FBB64B0D5C6C8499E541A").expect("Can't get iv from hex");
    let ciphertext_rs = encrypt(cipher, &key, Some(&iv), b"hello").unwrap().to_base64(base64::STANDARD);
    
    assert_eq!(ciphertext_py, ciphertext_rs);
}

