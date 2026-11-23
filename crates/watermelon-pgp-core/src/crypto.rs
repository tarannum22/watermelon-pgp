//! The only module that talks to rPGP. Everything else works with the types defined here,
//! so the OpenPGP backend can be swapped without touching the rest of the code base.

use std::{
    fmt,
    io::{self, BufRead, Read, Write},
};

use pgp::{
    composed::{
        ArmorOptions, DecryptionOptions, Deserializable, EncryptionCaps, KeyType, Message,
        MessageBuilder, PublicOrSecret, SecretKeyParamsBuilder, SignedPublicSubKey,
        SubkeyParamsBuilder, TheRing, VerificationResult,
    },
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        ecc_curve::ECCCurve,
        hash::HashAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::{Signature, SignatureType},
    ser::Serialize,
    types::{
        CompressionAlgorithm, KeyDetails, Password, Seipdv1ReadMode, SigningKey, VerifyingKey,
    },
};
use rand::rngs::OsRng;
use smallvec::smallvec;

use crate::{Error, Result};

pub use pgp::composed::{SignedPublicKey, SignedSecretKey};

/// Algorithms offered when generating a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// EdDSA primary key with an ECDH Curve25519 encryption subkey, in the v4 "legacy" encoding
    /// that GnuPG 2.2 and later understand.
    Curve25519,
    /// RSA-4096 primary key and encryption subkey, for partners with old tooling.
    Rsa4096,
}

/// Encrypted container format for encryption jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Container {
    /// SEIPD v1 (MDC). Readable by every OpenPGP implementation in use today.
    #[default]
    SeipdV1,
    /// SEIPD v2 (RFC 9580 AEAD). Opt-in for partners known to support it.
    SeipdV2,
}

/// A parsed certificate, with or without secret key material.
#[derive(Debug, Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "certs are short-lived and handled a few at a time"
)]
pub enum Cert {
    Public(SignedPublicKey),
    Secret(SignedSecretKey),
}

/// What we display and index about a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// Upper-case hex fingerprint of the primary key.
    pub fingerprint: String,
    pub user_ids: Vec<String>,
    pub algorithm: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds; `None` means the key does not expire.
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub has_secret: bool,
    pub can_encrypt: bool,
    pub can_sign: bool,
}

impl KeyInfo {
    /// The user ID shown as the key's name: the primary one, else the first, else a placeholder.
    pub fn label(&self) -> &str {
        self.user_ids
            .first()
            .map(String::as_str)
            .unwrap_or("(no user ID)")
    }
}

/// Result of checking signatures on a decrypted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureCheck {
    /// The message carried no signature.
    Unsigned,
    /// At least one signature verified against the certificate with this fingerprint.
    Valid { signer: String },
    /// The message was signed, but no signature verified against the given certificates.
    Unverified,
}

impl Cert {
    pub fn public(&self) -> SignedPublicKey {
        match self {
            Cert::Public(cert) => cert.clone(),
            Cert::Secret(key) => key.to_public_key(),
        }
    }

    pub fn info(&self) -> KeyInfo {
        let public = self.public();
        let flags = primary_self_signature(&public).map(|sig| sig.key_flags());
        let usable_subkeys: Vec<_> = public
            .public_subkeys
            .iter()
            .filter(|sub| subkey_usable(sub))
            .collect();
        let can_encrypt = flags
            .as_ref()
            .is_some_and(|f| f.encrypt_comms() || f.encrypt_storage())
            || usable_subkeys.iter().any(|sub| subkey_can_encrypt(sub));
        let can_sign = flags.as_ref().is_some_and(|f| f.sign())
            || usable_subkeys.iter().any(|sub| subkey_can_sign(sub));

        let mut user_ids: Vec<(bool, String)> = public
            .details
            .users
            .iter()
            .map(|user| {
                let id = String::from_utf8_lossy(user.id.id()).into_owned();
                (user.is_primary(), id)
            })
            .collect();
        // Primary user ID first, the rest in certificate order.
        user_ids.sort_by_key(|(primary, _)| !primary);

        KeyInfo {
            fingerprint: fingerprint(&public),
            user_ids: user_ids.into_iter().map(|(_, id)| id).collect(),
            algorithm: algorithm_name(&public),
            created_at: public.created_at().as_secs().into(),
            expires_at: expires_at(&public),
            revoked: !public.details.revocation_signatures.is_empty(),
            has_secret: matches!(self, Cert::Secret(_)),
            can_encrypt,
            can_sign,
        }
    }

    /// Binary OpenPGP serialization, used for storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Cert::Public(cert) => cert.to_bytes()?,
            Cert::Secret(key) => key.to_bytes()?,
        })
    }

    /// Whether any secret key material is still passphrase-protected.
    pub fn is_locked(&self) -> bool {
        match self {
            Cert::Public(_) => false,
            Cert::Secret(key) => {
                key.primary_key.secret_params().is_encrypted()
                    || key
                        .secret_subkeys
                        .iter()
                        .any(|sub| sub.key.secret_params().is_encrypted())
            }
        }
    }

    /// Remove passphrase protection from all secret key material, so the key can be stored
    /// under the master key and used unattended.
    pub fn unlock(&mut self, passphrase: &str) -> Result<()> {
        if let Cert::Secret(key) = self {
            let pw = Password::from(passphrase);
            key.primary_key
                .remove_password(&pw)
                .map_err(|_| Error::Invalid("wrong passphrase".into()))?;
            for sub in &mut key.secret_subkeys {
                sub.key
                    .remove_password(&pw)
                    .map_err(|_| Error::Invalid("wrong passphrase".into()))?;
            }
        }
        Ok(())
    }
}

/// Generate a new v4 key with a certifying/signing primary key and an encryption subkey.
pub fn generate(user_id: &str, algorithm: Algorithm) -> Result<SignedSecretKey> {
    let (primary_type, encryption_type) = match algorithm {
        Algorithm::Curve25519 => (
            KeyType::Ed25519Legacy,
            KeyType::ECDH(ECCCurve::Curve25519Legacy),
        ),
        Algorithm::Rsa4096 => (KeyType::Rsa(4096), KeyType::Rsa(4096)),
    };

    let encryption_subkey = SubkeyParamsBuilder::default()
        .key_type(encryption_type)
        .can_encrypt(EncryptionCaps::All)
        .build()
        .map_err(|e| Error::Invalid(e.to_string()))?;

    let params = SecretKeyParamsBuilder::default()
        .key_type(primary_type)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(user_id.into())
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha256,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::ZIP,
        ])
        .subkeys(vec![encryption_subkey])
        .build()
        .map_err(|e| Error::Invalid(e.to_string()))?;

    Ok(params.generate(OsRng)?)
}

/// Parse every certificate in `data`, which may be ASCII-armored or binary.
/// Binding signatures are verified; a certificate that fails verification is an error.
pub fn parse_certs(data: &[u8]) -> Result<Vec<Cert>> {
    let (certs, _headers) = PublicOrSecret::from_reader_many(data)?;
    let mut out = Vec::new();
    for cert in certs {
        let cert = cert?;
        cert.verify_bindings()?;
        out.push(match cert {
            PublicOrSecret::Secret(key) => Cert::Secret(key),
            PublicOrSecret::Public(cert) => Cert::Public(cert),
        });
    }
    if out.is_empty() {
        return Err(Error::Invalid("no OpenPGP keys found".into()));
    }
    Ok(out)
}

/// Load a certificate stored by [`Cert::to_bytes`].
pub fn public_from_bytes(data: &[u8]) -> Result<SignedPublicKey> {
    Ok(SignedPublicKey::from_bytes(data)?)
}

/// Load a secret key stored by [`Cert::to_bytes`].
pub fn secret_from_bytes(data: &[u8]) -> Result<SignedSecretKey> {
    Ok(SignedSecretKey::from_bytes(data)?)
}

pub fn armor_public(cert: &SignedPublicKey) -> Result<String> {
    Ok(cert.to_armored_string(ArmorOptions::default())?)
}

/// Armor a secret key, protecting every secret component with `passphrase`.
pub fn armor_secret(key: &SignedSecretKey, passphrase: &str) -> Result<String> {
    if passphrase.is_empty() {
        return Err(Error::Invalid(
            "a passphrase is required to export a secret key".into(),
        ));
    }
    let pw = Password::from(passphrase);
    let mut key = key.clone();
    key.primary_key.set_password(OsRng, &pw)?;
    for sub in &mut key.secret_subkeys {
        sub.key.set_password(OsRng, &pw)?;
    }
    Ok(key.to_armored_string(ArmorOptions::default())?)
}

pub fn fingerprint(cert: &SignedPublicKey) -> String {
    format!("{:X}", cert.fingerprint())
}

/// Options for [`encrypt`].
pub struct EncryptOptions<'a> {
    pub recipients: &'a [SignedPublicKey],
    pub signer: Option<&'a SignedSecretKey>,
    pub container: Container,
    pub armor: bool,
    /// File name recorded in the literal data packet.
    pub file_name: &'a str,
}

/// Stream `input` into an encrypted OpenPGP message on `output`.
pub fn encrypt<R: Read, W: Write>(input: R, output: W, opts: &EncryptOptions<'_>) -> Result<()> {
    if opts.recipients.is_empty() {
        return Err(Error::Invalid("at least one recipient is required".into()));
    }
    let mut encryption_keys = Vec::new();
    for cert in opts.recipients {
        let keys = encryption_keys_of(cert);
        if keys.is_empty() {
            return Err(Error::Invalid(format!(
                "key {} has no usable encryption key",
                fingerprint(cert)
            )));
        }
        encryption_keys.extend(keys);
    }
    let signing_key = opts.signer.map(signing_key_of).transpose()?;
    let builder = MessageBuilder::from_reader(opts.file_name.to_owned(), input);

    // The two container types are different builder types, so the shared steps are a macro.
    macro_rules! finish {
        ($builder:expr) => {{
            let mut builder = $builder;
            for key in &encryption_keys {
                match key {
                    EncryptionTarget::Primary(cert) => builder.encrypt_to_key(OsRng, *cert)?,
                    EncryptionTarget::Subkey(sub) => builder.encrypt_to_key(OsRng, *sub)?,
                };
            }
            if let Some(key) = &signing_key {
                builder.sign(*key, Password::empty(), HashAlgorithm::Sha256);
            }
            if opts.armor {
                builder.to_armored_writer(OsRng, ArmorOptions::default(), output)?;
            } else {
                builder.to_writer(OsRng, output)?;
            }
        }};
    }

    match opts.container {
        Container::SeipdV1 => finish!(builder.seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256)),
        Container::SeipdV2 => finish!(builder.seipd_v2(
            OsRng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
        )),
    }
    Ok(())
}

/// Stream-decrypt `input` (armored or binary) into `output`, then check signatures against
/// `verifiers`.
///
/// SEIPD v1 data is decrypted in streaming mode: plaintext is written to `output` before the
/// integrity check at the end of the message. Callers must write to a location nobody reads
/// from (a temp file) and only publish it once this function has returned `Ok`.
pub fn decrypt<R, W>(
    input: R,
    mut output: W,
    keys: &[SignedSecretKey],
    verifiers: &[SignedPublicKey],
) -> Result<SignatureCheck>
where
    R: BufRead + fmt::Debug + Send,
    W: Write,
{
    let (message, _headers) = Message::from_reader(input)?;
    if !message.is_encrypted() {
        return Err(Error::Invalid(
            "input is not an encrypted OpenPGP message".into(),
        ));
    }
    let passwords: Vec<Password> = keys.iter().map(|_| Password::empty()).collect();
    let ring = TheRing {
        secret_keys: keys.iter().collect(),
        key_passwords: passwords.iter().collect(),
        decrypt_options: DecryptionOptions::new()
            .set_seipdv1_read_mode(Seipdv1ReadMode::Streaming)
            .enable_gnupg_aead(),
        ..Default::default()
    };
    let (mut message, _) = message.decrypt_the_ring(ring, true).map_err(|e| match e {
        pgp::errors::Error::MissingKey => {
            Error::Invalid("none of the configured keys can decrypt this message".into())
        }
        e => e.into(),
    })?;
    while message.is_compressed() {
        message = message.decompress()?;
    }
    io::copy(&mut message, &mut output).map_err(|e| {
        Error::Invalid(format!(
            "decryption failed (corrupt or tampered input?): {e}"
        ))
    })?;
    output.flush()?;

    if !message.is_signed() {
        return Ok(SignatureCheck::Unsigned);
    }
    for cert in verifiers {
        let candidates = verifying_keys_of(cert);
        let results = message.verify_nested(&candidates)?;
        if results
            .iter()
            .any(|r| matches!(r, VerificationResult::Valid(_)))
        {
            return Ok(SignatureCheck::Valid {
                signer: fingerprint(cert),
            });
        }
    }
    Ok(SignatureCheck::Unverified)
}

enum EncryptionTarget<'a> {
    Primary(&'a SignedPublicKey),
    Subkey(&'a SignedPublicSubKey),
}

fn encryption_keys_of(cert: &SignedPublicKey) -> Vec<EncryptionTarget<'_>> {
    let subkeys: Vec<_> = cert
        .public_subkeys
        .iter()
        .filter(|sub| subkey_usable(sub) && subkey_can_encrypt(sub))
        .map(EncryptionTarget::Subkey)
        .collect();
    if !subkeys.is_empty() {
        return subkeys;
    }
    let primary_encrypts = primary_self_signature(cert)
        .is_some_and(|sig| sig.key_flags().encrypt_comms() || sig.key_flags().encrypt_storage());
    if primary_encrypts {
        vec![EncryptionTarget::Primary(cert)]
    } else {
        Vec::new()
    }
}

fn signing_key_of(key: &SignedSecretKey) -> Result<&dyn SigningKey> {
    let public = key.to_public_key();
    for (secret, public_sub) in key.secret_subkeys.iter().zip(&public.public_subkeys) {
        if subkey_usable(public_sub) && subkey_can_sign(public_sub) {
            return Ok(&secret.key);
        }
    }
    if primary_self_signature(&public).is_some_and(|sig| sig.key_flags().sign()) {
        return Ok(&key.primary_key);
    }
    Err(Error::Invalid(format!(
        "key {} cannot sign",
        fingerprint(&public)
    )))
}

fn verifying_keys_of(cert: &SignedPublicKey) -> Vec<&dyn VerifyingKey> {
    let mut keys: Vec<&dyn VerifyingKey> = vec![cert];
    keys.extend(
        cert.public_subkeys
            .iter()
            .map(|sub| sub as &dyn VerifyingKey),
    );
    keys
}

/// The most recent self-signature carrying the primary key's flags and expiry.
fn primary_self_signature(cert: &SignedPublicKey) -> Option<&Signature> {
    cert.details
        .direct_signatures
        .iter()
        .chain(cert.details.users.iter().flat_map(|user| &user.signatures))
        .filter(|sig| sig.created().is_some())
        .max_by_key(|sig| sig.created().map(|t| t.as_secs()))
}

fn latest_binding(sub: &SignedPublicSubKey) -> Option<&Signature> {
    sub.signatures
        .iter()
        .filter(|sig| sig.typ() == Some(SignatureType::SubkeyBinding))
        .max_by_key(|sig| sig.created().map(|t| t.as_secs()))
}

fn subkey_usable(sub: &SignedPublicSubKey) -> bool {
    let revoked = sub
        .signatures
        .iter()
        .any(|sig| sig.typ() == Some(SignatureType::SubkeyRevocation));
    let Some(binding) = latest_binding(sub) else {
        return false;
    };
    let expired = binding.key_expiration_time().is_some_and(|validity| {
        validity.as_secs() != 0
            && i64::from(sub.created_at().as_secs()) + i64::from(validity.as_secs()) <= now()
    });
    !revoked && !expired
}

fn subkey_can_encrypt(sub: &SignedPublicSubKey) -> bool {
    latest_binding(sub).is_some_and(|sig| {
        let flags = sig.key_flags();
        flags.encrypt_comms() || flags.encrypt_storage()
    })
}

fn subkey_can_sign(sub: &SignedPublicSubKey) -> bool {
    latest_binding(sub).is_some_and(|sig| sig.key_flags().sign())
}

fn expires_at(cert: &SignedPublicKey) -> Option<i64> {
    let validity = primary_self_signature(cert)?.key_expiration_time()?;
    (validity.as_secs() != 0)
        .then(|| i64::from(cert.created_at().as_secs()) + i64::from(validity.as_secs()))
}

fn algorithm_name(cert: &SignedPublicKey) -> String {
    use pgp::crypto::public_key::PublicKeyAlgorithm as Alg;
    use pgp::types::PublicParams;
    match (cert.algorithm(), cert.public_params()) {
        (Alg::RSA | Alg::RSAEncrypt | Alg::RSASign, PublicParams::RSA(rsa)) => {
            use rsa::traits::PublicKeyParts;
            format!("RSA-{}", rsa.key.n().bits())
        }
        (Alg::EdDSALegacy | Alg::Ed25519, _) => "Ed25519".into(),
        (Alg::Ed448, _) => "Ed448".into(),
        (alg, _) => format!("{alg:?}"),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(
        algorithm: Algorithm,
        container: Container,
        armor: bool,
        sign: bool,
    ) -> SignatureCheck {
        let recipient = generate("Recipient <r@example.com>", algorithm).unwrap();
        let sender = generate("Sender <s@example.com>", Algorithm::Curve25519).unwrap();
        let plaintext = b"id,name\n1,alice\n2,bob\n".repeat(1000);

        let mut encrypted = Vec::new();
        encrypt(
            &plaintext[..],
            &mut encrypted,
            &EncryptOptions {
                recipients: &[recipient.to_public_key()],
                signer: sign.then_some(&sender),
                container,
                armor,
                file_name: "customers.csv",
            },
        )
        .unwrap();
        assert_eq!(armor, encrypted.starts_with(b"-----BEGIN PGP MESSAGE-----"));

        let mut decrypted = Vec::new();
        let check = decrypt(
            &encrypted[..],
            &mut decrypted,
            &[recipient],
            &[sender.to_public_key()],
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
        check
    }

    #[test]
    fn roundtrips_all_combinations() {
        for algorithm in [Algorithm::Curve25519, Algorithm::Rsa4096] {
            for container in [Container::SeipdV1, Container::SeipdV2] {
                for armor in [false, true] {
                    assert_eq!(
                        roundtrip(algorithm, container, armor, false),
                        SignatureCheck::Unsigned
                    );
                    assert!(matches!(
                        roundtrip(algorithm, container, armor, true),
                        SignatureCheck::Valid { .. }
                    ));
                }
            }
        }
    }

    #[test]
    fn signature_from_unknown_key_is_unverified() {
        let recipient = generate("R", Algorithm::Curve25519).unwrap();
        let sender = generate("S", Algorithm::Curve25519).unwrap();
        let stranger = generate("X", Algorithm::Curve25519).unwrap();
        let mut encrypted = Vec::new();
        encrypt(
            &b"data"[..],
            &mut encrypted,
            &EncryptOptions {
                recipients: &[recipient.to_public_key()],
                signer: Some(&sender),
                container: Container::SeipdV1,
                armor: false,
                file_name: "f",
            },
        )
        .unwrap();
        let check = decrypt(
            &encrypted[..],
            &mut Vec::new(),
            &[recipient],
            &[stranger.to_public_key()],
        )
        .unwrap();
        assert_eq!(check, SignatureCheck::Unverified);
    }

    #[test]
    fn tampered_seipd_v1_fails() {
        let recipient = generate("R", Algorithm::Curve25519).unwrap();
        let mut encrypted = Vec::new();
        encrypt(
            &vec![7u8; 200_000][..],
            &mut encrypted,
            &EncryptOptions {
                recipients: &[recipient.to_public_key()],
                signer: None,
                container: Container::SeipdV1,
                armor: false,
                file_name: "f",
            },
        )
        .unwrap();
        let mid = encrypted.len() / 2;
        encrypted[mid] ^= 0x01;
        let result = decrypt(&encrypted[..], &mut Vec::new(), &[recipient], &[]);
        assert!(result.is_err(), "tampered message must not decrypt cleanly");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let recipient = generate("R", Algorithm::Curve25519).unwrap();
        let other = generate("O", Algorithm::Curve25519).unwrap();
        let mut encrypted = Vec::new();
        encrypt(
            &b"data"[..],
            &mut encrypted,
            &EncryptOptions {
                recipients: &[recipient.to_public_key()],
                signer: None,
                container: Container::SeipdV1,
                armor: false,
                file_name: "f",
            },
        )
        .unwrap();
        assert!(decrypt(&encrypted[..], &mut Vec::new(), &[other], &[]).is_err());
    }

    #[test]
    fn secret_export_reimports_with_passphrase() {
        let key = generate("R <r@example.com>", Algorithm::Curve25519).unwrap();
        let armored = armor_secret(&key, "correct horse").unwrap();
        let mut certs = parse_certs(armored.as_bytes()).unwrap();
        assert_eq!(certs.len(), 1);
        let cert = &mut certs[0];
        assert!(cert.is_locked());
        assert!(cert.unlock("wrong").is_err());
        cert.unlock("correct horse").unwrap();
        assert!(!cert.is_locked());
        let info = cert.info();
        assert_eq!(info.fingerprint, fingerprint(&key.to_public_key()));
        assert_eq!(info.user_ids, vec!["R <r@example.com>"]);
        assert!(info.has_secret && info.can_encrypt && info.can_sign);
        assert_eq!(info.algorithm, "Ed25519");
        assert_eq!(info.expires_at, None);
    }
}
