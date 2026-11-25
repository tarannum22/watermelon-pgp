//! Envelope encryption of secret key material under the master key.
//!
//! Every secret key is stored sealed with XChaCha20-Poly1305 under a 256-bit master key that
//! lives outside the database (a `0600` keyfile or an environment variable). The sealed blob is
//! bound to a context string, so a blob copied onto another row does not open.

use std::{fs, path::Path};

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

use crate::{Error, Result, platform};

/// Environment variable that, when set, takes precedence over the keyfile.
pub const ENV_VAR: &str = "WATERMELON_MASTER_KEY";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
/// Leading byte of every sealed blob, so the scheme can change without ambiguity.
const SEAL_V1: u8 = 1;

pub struct MasterKey(Zeroizing<[u8; KEY_LEN]>);

impl MasterKey {
    pub fn generate() -> Self {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(&mut *key);
        Self(key)
    }

    pub fn from_hex(hex_key: &str) -> Result<Self> {
        let bytes = Zeroizing::new(
            hex::decode(hex_key.trim()).map_err(|_| Error::MasterKey("not valid hex".into()))?,
        );
        let key: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::MasterKey(format!("expected {KEY_LEN} bytes")))?;
        Ok(Self(Zeroizing::new(key)))
    }

    /// Load from [`ENV_VAR`] if set, otherwise from the keyfile at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        if let Ok(value) = std::env::var(ENV_VAR) {
            return Self::from_hex(&Zeroizing::new(value));
        }
        let contents = Zeroizing::new(
            fs::read_to_string(path)
                .map_err(|e| Error::MasterKey(format!("{}: {e}", path.display())))?,
        );
        if platform::is_readable_by_others(path)? {
            return Err(Error::MasterKey(format!(
                "{} is readable by other users; restrict it with `{}`",
                path.display(),
                platform::restrict_hint(path)
            )));
        }
        Self::from_hex(&contents)
    }

    /// Write this key to a new keyfile only the current user can read. Never overwrites.
    pub fn write_new(&self, path: &Path) -> Result<()> {
        let mut contents = Zeroizing::new(hex::encode(*self.0));
        contents.push('\n');
        platform::write_private_file(path, contents.as_bytes())?;
        Ok(())
    }

    pub fn seal(&self, plaintext: &[u8], context: &str) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad(context),
                },
            )
            .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail");
        let mut sealed = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        sealed.push(SEAL_V1);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        sealed
    }

    pub fn open(&self, sealed: &[u8], context: &str) -> Result<Zeroizing<Vec<u8>>> {
        let (&version, rest) = sealed.split_first().ok_or(Error::Unseal)?;
        if version != SEAL_V1 || rest.len() < NONCE_LEN {
            return Err(Error::Unseal);
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        self.cipher()
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad(context),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::Unseal)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(&*self.0))
    }
}

fn aad(context: &str) -> Vec<u8> {
    let mut aad = vec![SEAL_V1];
    aad.extend_from_slice(context.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_binding() {
        let key = MasterKey::generate();
        let sealed = key.seal(b"secret", "key:AAAA");
        assert_eq!(&**key.open(&sealed, "key:AAAA").unwrap(), b"secret");
        assert!(key.open(&sealed, "key:BBBB").is_err());
        assert!(MasterKey::generate().open(&sealed, "key:AAAA").is_err());

        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(key.open(&tampered, "key:AAAA").is_err());
    }

    #[test]
    fn keyfile_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        let key = MasterKey::generate();
        key.write_new(&path).unwrap();
        assert!(key.write_new(&path).is_err(), "must never overwrite");
        let loaded = MasterKey::load(&path).unwrap();
        let sealed = key.seal(b"x", "c");
        assert_eq!(&**loaded.open(&sealed, "c").unwrap(), b"x");
    }

    #[test]
    fn rejects_world_readable_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        MasterKey::generate().write_new(&path).unwrap();
        crate::platform::testing::grant_others_read(&path);
        let err = MasterKey::load(&path).err().unwrap().to_string();
        assert!(err.contains("readable by other users"), "{err}");
    }
}
