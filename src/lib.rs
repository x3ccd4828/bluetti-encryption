#![no_std]

extern crate alloc;

use alloc::format;

pub mod ffi;

/// Bluetti BLE Encryption Implementation
///
/// This module implements the Bluetti device encryption protocol:
/// 1. Device sends CHALLENGE (4-byte seed)
/// 2. Client generates unsecure_aes_key from seed
/// 3. Device sends PEER_PUBKEY (signed with K2)
/// 4. Client generates local keypair, signs with L1, sends back
/// 5. Device confirms PUBKEY_ACCEPTED
/// 6. Client calculates secure_aes_key via ECDH
/// 7. All subsequent MODBUS commands encrypted with secure_aes_key
use aes::{Aes128, Aes256};
use cbc::{
    Decryptor, Encryptor,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding},
};
use heapless::Vec;
use md5::{Digest, Md5};
use p256::{
    PublicKey,
    ecdh::EphemeralSecret,
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    elliptic_curve::{Generate, sec1::ToSec1Point},
};

const LOCAL_AES_KEY: [u8; 16] = hex_literal::hex!("459FC535808941F17091E0993EE3E93D");
const PRIVATE_KEY_L1: [u8; 32] =
    hex_literal::hex!("4F19A16E3E87BDD9BD24D3E5495B88041511943CBC8B969ADE9641D0F56AF337");
const PUBLIC_KEY_K2_BYTES: [u8; 91] = hex_literal::hex!(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004A73ABF5D2232C8C1C72E68304343C272495E3A8FD6F30EA96DE2F4B3CE60B251EE21AC667CF8A71E18B46B664EAEFFE3C489F24F695B6411DB7E22CCC85A8594"
);

const KEX_MAGIC: [u8; 2] = [0x2A, 0x2A];
const AES_BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Challenge = 1,
    ChallengeAccepted = 3,
    PeerPubkey = 4,
    PubkeyAccepted = 6,
}

impl MessageType {
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Challenge),
            3 => Some(Self::ChallengeAccepted),
            4 => Some(Self::PeerPubkey),
            6 => Some(Self::PubkeyAccepted),
            _ => None,
        }
    }
}

pub struct Message<'a> {
    buffer: &'a [u8],
}

impl<'a> Message<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }

    pub fn is_pre_key_exchange(&self) -> bool {
        self.buffer.len() >= 2 && self.buffer[0..2] == KEX_MAGIC
    }

    pub fn message_type(&self) -> Option<MessageType> {
        if self.buffer.len() >= 3 {
            MessageType::from_u8(self.buffer[2])
        } else {
            None
        }
    }

    pub fn data(&self) -> &[u8] {
        if self.buffer.len() > 4 {
            let end = self.buffer.len() - 2;
            &self.buffer[4..end]
        } else {
            &[]
        }
    }

    pub fn body(&self) -> &[u8] {
        if self.buffer.len() > 4 {
            let end = self.buffer.len() - 2;
            &self.buffer[2..end]
        } else {
            &[]
        }
    }

    pub fn verify_checksum(&self) -> bool {
        if self.buffer.len() < 4 {
            return false;
        }

        let body = self.body();
        let checksum = &self.buffer[self.buffer.len() - 2..];
        let computed = hexsum(body, 2);

        computed == checksum
    }
}

pub struct BluettiEncryption {
    unsecure_aes_key: Option<[u8; 16]>,
    unsecure_aes_iv: Option<[u8; 16]>,
    my_secret: Option<EphemeralSecret>,
    peer_pubkey: Option<PublicKey>,
    secure_aes_key: Option<[u8; 32]>,
}

impl Default for BluettiEncryption {
    fn default() -> Self {
        Self::new()
    }
}

impl BluettiEncryption {
    pub fn new() -> Self {
        Self {
            unsecure_aes_key: None,
            unsecure_aes_iv: None,
            my_secret: None,
            peer_pubkey: None,
            secure_aes_key: None,
        }
    }

    pub fn is_ready_for_commands(&self) -> bool {
        self.secure_aes_key.is_some() && self.peer_pubkey.is_some()
    }

    pub fn encrypt_modbus_command(&self, data: &[u8]) -> Result<Vec<u8, 512>, &'static str> {
        let key = self.secure_aes_key.as_ref().ok_or("Encryption not ready")?;
        self.aes_encrypt(data, key, None)
    }

    pub fn reset(&mut self) {
        self.unsecure_aes_key = None;
        self.unsecure_aes_iv = None;
        self.my_secret = None;
        self.peer_pubkey = None;
        self.secure_aes_key = None;
    }

    pub fn handle_challenge(&mut self, message: &Message) -> Result<Vec<u8, 256>, &'static str> {
        let data = message.data();
        if data.len() != 4 {
            return Err("Invalid challenge length");
        }

        let mut reversed = [0u8; 4];
        reversed.copy_from_slice(data);
        reversed.reverse();

        let mut hasher = Md5::new();
        hasher.update(reversed);
        let iv = hasher.finalize();
        let mut unsecure_iv = [0u8; 16];
        unsecure_iv.copy_from_slice(&iv);
        self.unsecure_aes_iv = Some(unsecure_iv);

        let mut unsecure_key = [0u8; 16];
        for i in 0..16 {
            unsecure_key[i] = unsecure_iv[i] ^ LOCAL_AES_KEY[i];
        }
        self.unsecure_aes_key = Some(unsecure_key);

        log::info!("Unsecure IV:  {:02x?}", unsecure_iv);
        log::info!("Unsecure Key: {:02x?}", unsecure_key);

        let mut response = Vec::new();
        let _ = response.extend_from_slice(&KEX_MAGIC);
        let _ = response.push(0x02);
        let _ = response.push(0x04);
        let _ = response.extend_from_slice(&unsecure_iv[8..12]);

        let checksum = hexsum(&response[2..], 2);
        let _ = response.extend_from_slice(&checksum);

        Ok(response)
    }

    pub fn handle_peer_pubkey<R>(
        &mut self,
        message: &Message,
        rng: &mut R,
    ) -> Result<Vec<u8, 512>, &'static str>
    where
        R: rand_core::TryCryptoRng,
    {
        let data = message.data();
        if data.len() != 128 {
            return Err("Invalid peer pubkey length");
        }

        let pubkey_bytes = &data[0..64];
        let signature_bytes = &data[64..128];

        let unsecure_iv = self.unsecure_aes_iv.ok_or("No unsecure IV")?;
        self.verify_peer_signature(pubkey_bytes, signature_bytes, &unsecure_iv)?;

        let mut pubkey_with_prefix = [0u8; 65];
        pubkey_with_prefix[0] = 0x04;
        pubkey_with_prefix[1..].copy_from_slice(pubkey_bytes);

        let peer_key = PublicKey::from_sec1_bytes(&pubkey_with_prefix)
            .map_err(|_| "Invalid peer public key")?;
        self.peer_pubkey = Some(peer_key);

        log::info!("Peer public key verified");

        let secret = EphemeralSecret::try_generate_from_rng(rng)
            .map_err(|_| "Failed to generate ephemeral key")?;
        let public = secret.public_key();
        self.my_secret = Some(secret);

        let my_pubkey_bytes = public.to_sec1_point(false);
        let my_pubkey_untagged = my_pubkey_bytes.as_bytes();
        let my_pubkey_64 = &my_pubkey_untagged[1..65];

        let signing_key =
            SigningKey::from_bytes(&PRIVATE_KEY_L1.into()).map_err(|_| "Invalid signing key")?;

        let mut to_sign = Vec::<u8, 80>::new();
        let _ = to_sign.extend_from_slice(my_pubkey_64);
        let _ = to_sign.extend_from_slice(&unsecure_iv);

        let signature: Signature = signing_key.sign(&to_sign);
        let sig_bytes = signature.to_bytes();

        let mut body = Vec::<u8, 256>::new();
        let _ = body.extend_from_slice(&KEX_MAGIC);
        let _ = body.push(0x05);
        let _ = body.push(0x80);
        let _ = body.extend_from_slice(my_pubkey_64);
        let _ = body.extend_from_slice(&sig_bytes[..]);

        let checksum = hexsum(&body[2..], 2);
        let _ = body.extend_from_slice(&checksum);

        let unsecure_key = self.unsecure_aes_key.ok_or("No unsecure key")?;
        self.aes_encrypt(&body, &unsecure_key, Some(unsecure_iv))
    }

    pub fn handle_pubkey_accepted(&mut self, message: &Message) -> Result<(), &'static str> {
        let data = message.data();
        if data.len() != 1 || data[0] != 0 {
            return Err("Invalid pubkey accepted response");
        }

        let my_secret = self.my_secret.take().ok_or("No secret key")?;
        let peer_pubkey = self.peer_pubkey.ok_or("No peer public key")?;

        let shared_secret = my_secret.diffie_hellman(&peer_pubkey);
        let mut secure_key = [0u8; 32];
        secure_key.copy_from_slice(shared_secret.raw_secret_bytes());
        self.secure_aes_key = Some(secure_key);

        log::info!("Secure key:   {:02x?}", secure_key);
        log::info!("Encryption handshake complete");

        Ok(())
    }

    pub fn aes_decrypt(&self, data: &[u8]) -> Result<Vec<u8, 512>, &'static str> {
        if data.len() < 6 {
            return Err("Data too short");
        }

        let data_len = ((data[0] as usize) << 8) | (data[1] as usize);

        if self.secure_aes_key.is_some() {
            let mut hasher = Md5::new();
            hasher.update(&data[2..6]);
            let iv_hash = hasher.finalize();
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&iv_hash);

            let key = self.secure_aes_key.as_ref().ok_or("No secure key")?;

            let encrypted = &data[6..];
            if !encrypted.len().is_multiple_of(AES_BLOCK_SIZE) {
                return Err("Data not aligned on AES block size");
            }

            let mut buffer = Vec::<u8, 512>::new();
            buffer
                .extend_from_slice(encrypted)
                .map_err(|_| "Buffer overflow")?;

            let decryptor = Decryptor::<Aes256>::new_from_slices(key, &iv)
                .map_err(|_| "Failed to create AES-256 decryptor")?;

            let decrypted = decryptor
                .decrypt_padded_mut::<NoPadding>(&mut buffer)
                .map_err(|_| "Decryption failed")?;

            let mut result = Vec::new();
            result
                .extend_from_slice(&decrypted[..data_len.min(decrypted.len())])
                .map_err(|_| "Buffer overflow")?;

            log::debug!("Decrypted: {:02x?}", result.as_slice());
            Ok(result)
        } else {
            let key = self.unsecure_aes_key.as_ref().ok_or("No unsecure key")?;
            let iv = self.unsecure_aes_iv.ok_or("No unsecure IV")?;

            let encrypted = &data[2..];
            if !encrypted.len().is_multiple_of(AES_BLOCK_SIZE) {
                return Err("Data not aligned on AES block size");
            }

            let mut buffer = Vec::<u8, 512>::new();
            buffer
                .extend_from_slice(encrypted)
                .map_err(|_| "Buffer overflow")?;

            let decryptor = Decryptor::<Aes128>::new_from_slices(&key[..], &iv)
                .map_err(|_| "Failed to create AES-128 decryptor")?;

            let decrypted = decryptor
                .decrypt_padded_mut::<NoPadding>(&mut buffer)
                .map_err(|_| "Decryption failed")?;

            let mut result = Vec::new();
            result
                .extend_from_slice(&decrypted[..data_len.min(decrypted.len())])
                .map_err(|_| "Buffer overflow")?;

            log::debug!("Decrypted: {:02x?}", result.as_slice());
            Ok(result)
        }
    }

    pub fn aes_encrypt(
        &self,
        data: &[u8],
        key: &[u8],
        iv_opt: Option<[u8; 16]>,
    ) -> Result<Vec<u8, 512>, &'static str> {
        let data_len = data.len();

        let mut result = Vec::new();
        result
            .push((data_len >> 8) as u8)
            .map_err(|_| "Buffer overflow")?;
        result
            .push((data_len & 0xFF) as u8)
            .map_err(|_| "Buffer overflow")?;

        let iv = if let Some(iv_fixed) = iv_opt {
            iv_fixed
        } else {
            let iv_seed = [0x12, 0x34, 0x56, 0x78];
            result
                .extend_from_slice(&iv_seed)
                .map_err(|_| "Buffer overflow")?;

            let mut hasher = Md5::new();
            hasher.update(iv_seed);
            let iv_hash = hasher.finalize();
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&iv_hash);
            iv
        };

        let padding = (AES_BLOCK_SIZE - data_len % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
        let mut padded = Vec::<u8, 512>::new();
        padded
            .extend_from_slice(data)
            .map_err(|_| "Buffer overflow")?;
        for _ in 0..padding {
            padded.push(0).map_err(|_| "Buffer overflow")?;
        }

        let mut buffer = padded.clone();

        if key.len() == 32 {
            let encryptor = Encryptor::<Aes256>::new_from_slices(key, &iv)
                .map_err(|_| "Failed to create AES-256 encryptor")?;

            let encrypted = encryptor
                .encrypt_padded_mut::<NoPadding>(&mut buffer, padded.len())
                .map_err(|_| "Encryption failed")?;

            result
                .extend_from_slice(encrypted)
                .map_err(|_| "Buffer overflow")?;
        } else {
            let encryptor = Encryptor::<Aes128>::new_from_slices(&key[..16], &iv)
                .map_err(|_| "Failed to create AES-128 encryptor")?;

            let encrypted = encryptor
                .encrypt_padded_mut::<NoPadding>(&mut buffer, padded.len())
                .map_err(|_| "Encryption failed")?;

            result
                .extend_from_slice(encrypted)
                .map_err(|_| "Buffer overflow")?;
        }

        log::debug!("Encrypted: {:02x?}", result.as_slice());
        Ok(result)
    }

    fn verify_peer_signature(
        &self,
        pubkey: &[u8],
        signature: &[u8],
        iv: &[u8],
    ) -> Result<(), &'static str> {
        let k2_bytes = &PUBLIC_KEY_K2_BYTES[PUBLIC_KEY_K2_BYTES.len() - 64..];
        let mut k2_with_prefix = [0u8; 65];
        k2_with_prefix[0] = 0x04;
        k2_with_prefix[1..].copy_from_slice(k2_bytes);

        let verifying_key =
            VerifyingKey::from_sec1_bytes(&k2_with_prefix).map_err(|_| "Invalid K2 key")?;

        let mut signed_data = Vec::<u8, 80>::new();
        signed_data
            .extend_from_slice(pubkey)
            .map_err(|_| "Buffer overflow")?;
        signed_data
            .extend_from_slice(iv)
            .map_err(|_| "Buffer overflow")?;

        let sig = Signature::from_slice(signature).map_err(|_| "Invalid signature format")?;

        verifying_key
            .verify(&signed_data, &sig)
            .map_err(|_| "Signature verification failed")?;

        Ok(())
    }
}

fn hexsum(data: &[u8], size: usize) -> Vec<u8, 4> {
    let sum: u32 = data.iter().map(|&b| b as u32).sum();
    let hex_str = format!("{:0width$x}", sum, width = size * 2);

    let mut result = Vec::new();
    let bytes = hex::decode(&hex_str).unwrap_or_default();
    let _ = result.extend_from_slice(&bytes);
    result
}
