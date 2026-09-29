//! The key derivations of KeePass files (KDBX 4), for the import: Argon2d and Argon2id, and the
//! older AES-KDF. Everything else of a KeePass file — its header, AES or ChaCha20, the XML — the
//! page reads itself (`src/lib/import/kdbx.ts`); these are the parts too slow for JavaScript.

use crate::{Failure, Result};
use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};

/// The most memory an Argon2 of a file may ask for: 2 GiB, more than any KeePass app offers by
/// default and still something a browser tab can hand out.
const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024;

/// Argon2 over the file's composite key (`key`, 32 bytes) with the file's parameters; `version`
/// is 0x10 or 0x13. Gives the 32-byte transformed key.
pub fn argon2(
    id: bool,
    version: u32,
    key: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> Result<Vec<u8>> {
    if memory_kib > MAX_MEMORY_KIB {
        return Err(Failure::new("unsupported", "This file asks for more memory than a browser can give it."));
    }
    let version = match version {
        0x10 => Version::V0x10,
        0x13 => Version::V0x13,
        _ => return Err(Failure::new("unsupported", "This file uses an Argon2 version this vault doesn't know.")),
    };
    let params = Params::new(memory_kib, iterations, lanes, Some(32))
        .map_err(|error| Failure::new("invalid", format!("Argon2 parameters of the file: {error}")))?;
    let algorithm = if id { Algorithm::Argon2id } else { Algorithm::Argon2d };
    let mut out = vec![0u8; 32];
    Argon2::new(algorithm, version, params)
        .hash_password_into(key, salt, &mut out)
        .map_err(|error| Failure::new("invalid", format!("Argon2: {error}")))?;
    Ok(out)
}

/// KeePass's AES-KDF: the composite key encrypted `rounds` times with AES-256 in ECB mode under
/// `seed`, then its SHA-256.
pub fn aes_kdf(key: &[u8], seed: &[u8], rounds: u64) -> Result<Vec<u8>> {
    if key.len() != 32 || seed.len() != 32 {
        return Err(Failure::new("invalid", "AES-KDF takes a 32-byte key and seed."));
    }
    let cipher = Aes256::new(GenericArray::from_slice(seed));
    let mut blocks = [GenericArray::clone_from_slice(&key[..16]), GenericArray::clone_from_slice(&key[16..])];
    for _ in 0..rounds {
        cipher.encrypt_blocks(&mut blocks);
    }
    let mut hash = Sha256::new();
    hash.update(blocks[0]);
    hash.update(blocks[1]);
    Ok(hash.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn argon2d_matches_the_reference() {
        // RFC 9106 needs secret and associated data; the reference tool's plain vector instead:
        // `echo -n password | argon2 somesalt -d -t 2 -m 16 -p 1 -l 32 -r` (version 0x13).
        let out = argon2(false, 0x13, b"password", b"somesalt", 1 << 16, 2, 1).unwrap();
        assert_eq!(hex(&out), "955e5d5b163a1b60bba35fc36d0496474fba4f6b59ad53628666f07fb2f93eaf");
    }

    #[test]
    fn aes_kdf_of_no_rounds_is_the_hash() {
        let key = [7u8; 32];
        let expected = Sha256::digest(key);
        assert_eq!(aes_kdf(&key, &[1u8; 32], 0).unwrap(), expected.to_vec());
        assert_ne!(aes_kdf(&key, &[1u8; 32], 1).unwrap(), expected.to_vec());
        assert!(aes_kdf(&key[..16], &[1u8; 32], 1).is_err());
    }

    #[test]
    fn too_much_memory_is_refused() {
        assert!(argon2(true, 0x13, b"k", b"saltsalt", MAX_MEMORY_KIB + 1, 1, 1).is_err());
    }
}
