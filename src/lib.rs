#![no_std]

extern crate alloc;

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
const CHECKSUM_SIZE: usize = 2;
const KEX_TYPE_OFFSET: usize = 2;
const KEX_BODY_OFFSET: usize = 2;
const KEX_DATA_OFFSET: usize = 4;
const CHALLENGE_LEN: usize = 4;
const PUBKEY_LEN: usize = 64;
const SIGNATURE_LEN: usize = 64;
const PEER_PUBKEY_PAYLOAD_LEN: usize = PUBKEY_LEN + SIGNATURE_LEN;
const SEC1_UNCOMPRESSED_PUBKEY_LEN: usize = PUBKEY_LEN + 1;
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
const CHALLENGE_RESPONSE_TYPE: u8 = 0x02;
const LOCAL_PUBKEY_TYPE: u8 = 0x05;
const CHALLENGE_IV_RESPONSE_START: usize = 8;
const CHALLENGE_IV_RESPONSE_END: usize = 12;
const IV_SEED: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

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
        self.buffer.starts_with(&KEX_MAGIC)
    }

    pub fn message_type(&self) -> Option<MessageType> {
        self.buffer
            .get(KEX_TYPE_OFFSET)
            .copied()
            .and_then(MessageType::from_u8)
    }

    pub fn data(&self) -> &[u8] {
        self.slice_without_checksum(KEX_DATA_OFFSET)
    }

    pub fn body(&self) -> &[u8] {
        self.slice_without_checksum(KEX_BODY_OFFSET)
    }

    pub fn verify_checksum(&self) -> bool {
        if self.buffer.len() < KEX_DATA_OFFSET {
            return false;
        }

        let Some(checksum_start) = self.buffer.len().checked_sub(CHECKSUM_SIZE) else {
            return false;
        };

        let checksum = &self.buffer[checksum_start..];
        let computed = hexsum(self.body(), CHECKSUM_SIZE);

        computed == checksum
    }

    fn slice_without_checksum(&self, start: usize) -> &[u8] {
        let end = self.buffer.len().saturating_sub(CHECKSUM_SIZE);
        self.buffer.get(start..end).unwrap_or(&[])
    }
}

pub struct BluettiEncryption {
    unsecure_aes_key: Option<[u8; 16]>,
    unsecure_aes_iv: Option<[u8; 16]>,
    my_secret: Option<EphemeralSecret>,
    peer_pubkey: Option<PublicKey>,
    secure_aes_key: Option<[u8; 32]>,
}

enum CipherKey<'a> {
    Aes128(&'a [u8; 16]),
    Aes256(&'a [u8; 32]),
}

impl<'a> CipherKey<'a> {
    fn from_slice(key: &'a [u8]) -> Result<Self, &'static str> {
        if let Ok(key_256) = <&[u8; 32]>::try_from(key) {
            return Ok(Self::Aes256(key_256));
        }

        let key_128: &[u8; 16] = key
            .get(..AES_BLOCK_SIZE)
            .ok_or("Invalid AES key length")?
            .try_into()
            .map_err(|_| "Invalid AES key length")?;

        Ok(Self::Aes128(key_128))
    }
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
        let mut reversed: [u8; CHALLENGE_LEN] = message
            .data()
            .try_into()
            .map_err(|_| "Invalid challenge length")?;
        reversed.reverse();

        let unsecure_iv = md5_hash_16(&reversed);
        let unsecure_key = xor_16(&unsecure_iv, &LOCAL_AES_KEY);

        self.unsecure_aes_iv = Some(unsecure_iv);
        self.unsecure_aes_key = Some(unsecure_key);

        log::info!("Unsecure IV:  {:02x?}", unsecure_iv);
        log::info!("Unsecure Key: {:02x?}", unsecure_key);

        build_kex_packet::<256>(
            CHALLENGE_RESPONSE_TYPE,
            &unsecure_iv[CHALLENGE_IV_RESPONSE_START..CHALLENGE_IV_RESPONSE_END],
        )
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
        if data.len() != PEER_PUBKEY_PAYLOAD_LEN {
            return Err("Invalid peer pubkey length");
        }

        let (pubkey_bytes, signature_bytes) = data.split_at(PUBKEY_LEN);

        let unsecure_iv = self.unsecure_aes_iv.ok_or("No unsecure IV")?;
        self.verify_peer_signature(pubkey_bytes, signature_bytes, &unsecure_iv)?;

        let mut pubkey_with_prefix = [0u8; SEC1_UNCOMPRESSED_PUBKEY_LEN];
        pubkey_with_prefix[0] = SEC1_UNCOMPRESSED_TAG;
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
        let my_pubkey_64 = my_pubkey_bytes
            .as_bytes()
            .get(1..SEC1_UNCOMPRESSED_PUBKEY_LEN)
            .ok_or("Invalid local public key length")?;

        let signing_key =
            SigningKey::from_bytes(&PRIVATE_KEY_L1.into()).map_err(|_| "Invalid signing key")?;

        let mut signed_data = [0u8; PUBKEY_LEN + AES_BLOCK_SIZE];
        signed_data[..PUBKEY_LEN].copy_from_slice(my_pubkey_64);
        signed_data[PUBKEY_LEN..].copy_from_slice(&unsecure_iv);

        let signature: Signature = signing_key.sign(&signed_data);
        let sig_bytes = signature.to_bytes();

        let mut payload = [0u8; PEER_PUBKEY_PAYLOAD_LEN];
        payload[..PUBKEY_LEN].copy_from_slice(my_pubkey_64);
        payload[PUBKEY_LEN..].copy_from_slice(&sig_bytes[..]);

        let body = build_kex_packet::<256>(LOCAL_PUBKEY_TYPE, &payload)?;

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

        let decrypted = if let Some(key) = self.secure_aes_key.as_ref() {
            let iv = md5_hash_16(&data[2..6]);
            decrypt_payload(&data[6..], data_len, CipherKey::Aes256(key), &iv)?
        } else {
            let key = self.unsecure_aes_key.as_ref().ok_or("No unsecure key")?;
            let iv = self.unsecure_aes_iv.ok_or("No unsecure IV")?;
            decrypt_payload(&data[2..], data_len, CipherKey::Aes128(key), &iv)?
        };

        log::debug!("Decrypted: {:02x?}", decrypted.as_slice());
        Ok(decrypted)
    }

    pub fn aes_encrypt(
        &self,
        data: &[u8],
        key: &[u8],
        iv_opt: Option<[u8; 16]>,
    ) -> Result<Vec<u8, 512>, &'static str> {
        let mut result = Vec::<u8, 512>::new();
        let data_len = data.len();

        result
            .push((data_len >> 8) as u8)
            .map_err(|_| "Buffer overflow")?;
        result
            .push((data_len & 0xFF) as u8)
            .map_err(|_| "Buffer overflow")?;

        let iv = match iv_opt {
            Some(iv) => iv,
            None => {
                result
                    .extend_from_slice(&IV_SEED)
                    .map_err(|_| "Buffer overflow")?;

                md5_hash_16(&IV_SEED)
            }
        };

        let mut buffer = zero_pad(data)?;
        let encrypted = encrypt_payload(&mut buffer, CipherKey::from_slice(key)?, &iv)?;

        result
            .extend_from_slice(encrypted)
            .map_err(|_| "Buffer overflow")?;

        log::debug!("Encrypted: {:02x?}", result.as_slice());
        Ok(result)
    }

    fn verify_peer_signature(
        &self,
        pubkey: &[u8],
        signature: &[u8],
        iv: &[u8],
    ) -> Result<(), &'static str> {
        if pubkey.len() != PUBKEY_LEN
            || signature.len() != SIGNATURE_LEN
            || iv.len() != AES_BLOCK_SIZE
        {
            return Err("Invalid signature payload");
        }

        let k2_bytes = PUBLIC_KEY_K2_BYTES
            .get(PUBLIC_KEY_K2_BYTES.len() - PUBKEY_LEN..)
            .ok_or("Invalid K2 key")?;

        let mut k2_with_prefix = [0u8; SEC1_UNCOMPRESSED_PUBKEY_LEN];
        k2_with_prefix[0] = SEC1_UNCOMPRESSED_TAG;
        k2_with_prefix[1..].copy_from_slice(k2_bytes);

        let verifying_key =
            VerifyingKey::from_sec1_bytes(&k2_with_prefix).map_err(|_| "Invalid K2 key")?;

        let mut signed_data = [0u8; PUBKEY_LEN + AES_BLOCK_SIZE];
        signed_data[..PUBKEY_LEN].copy_from_slice(pubkey);
        signed_data[PUBKEY_LEN..].copy_from_slice(iv);

        let sig = Signature::from_slice(signature).map_err(|_| "Invalid signature format")?;

        verifying_key
            .verify(&signed_data, &sig)
            .map_err(|_| "Signature verification failed")?;

        Ok(())
    }
}

fn build_kex_packet<const N: usize>(
    message_type: u8,
    payload: &[u8],
) -> Result<Vec<u8, N>, &'static str> {
    let payload_len = u8::try_from(payload.len()).map_err(|_| "Payload too large")?;

    let mut packet = Vec::<u8, N>::new();
    packet
        .extend_from_slice(&KEX_MAGIC)
        .map_err(|_| "Buffer overflow")?;
    packet.push(message_type).map_err(|_| "Buffer overflow")?;
    packet.push(payload_len).map_err(|_| "Buffer overflow")?;
    packet
        .extend_from_slice(payload)
        .map_err(|_| "Buffer overflow")?;

    let checksum = hexsum(&packet[KEX_BODY_OFFSET..], CHECKSUM_SIZE);
    packet
        .extend_from_slice(&checksum)
        .map_err(|_| "Buffer overflow")?;

    Ok(packet)
}

fn md5_hash_16(input: &[u8]) -> [u8; AES_BLOCK_SIZE] {
    let mut hasher = Md5::new();
    hasher.update(input);

    let digest = hasher.finalize();
    let mut output = [0u8; AES_BLOCK_SIZE];
    output.copy_from_slice(&digest);
    output
}

fn xor_16(lhs: &[u8; AES_BLOCK_SIZE], rhs: &[u8; AES_BLOCK_SIZE]) -> [u8; AES_BLOCK_SIZE] {
    let mut output = [0u8; AES_BLOCK_SIZE];

    for (dst, (&left, &right)) in output.iter_mut().zip(lhs.iter().zip(rhs.iter())) {
        *dst = left ^ right;
    }

    output
}

fn decrypt_payload(
    encrypted: &[u8],
    data_len: usize,
    key: CipherKey<'_>,
    iv: &[u8; AES_BLOCK_SIZE],
) -> Result<Vec<u8, 512>, &'static str> {
    if !encrypted.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err("Data not aligned on AES block size");
    }

    let mut buffer = Vec::<u8, 512>::new();
    buffer
        .extend_from_slice(encrypted)
        .map_err(|_| "Buffer overflow")?;

    let decrypted = match key {
        CipherKey::Aes256(key) => Decryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|_| "Failed to create AES-256 decryptor")?
            .decrypt_padded_mut::<NoPadding>(&mut buffer)
            .map_err(|_| "Decryption failed")?,
        CipherKey::Aes128(key) => Decryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| "Failed to create AES-128 decryptor")?
            .decrypt_padded_mut::<NoPadding>(&mut buffer)
            .map_err(|_| "Decryption failed")?,
    };

    let mut result = Vec::<u8, 512>::new();
    result
        .extend_from_slice(&decrypted[..data_len.min(decrypted.len())])
        .map_err(|_| "Buffer overflow")?;

    Ok(result)
}

fn zero_pad(data: &[u8]) -> Result<Vec<u8, 512>, &'static str> {
    let mut padded = Vec::<u8, 512>::new();
    padded
        .extend_from_slice(data)
        .map_err(|_| "Buffer overflow")?;

    let padding = (AES_BLOCK_SIZE - data.len() % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
    for _ in 0..padding {
        padded.push(0).map_err(|_| "Buffer overflow")?;
    }

    Ok(padded)
}

fn encrypt_payload<'a>(
    buffer: &'a mut Vec<u8, 512>,
    key: CipherKey<'_>,
    iv: &[u8; AES_BLOCK_SIZE],
) -> Result<&'a [u8], &'static str> {
    let plain_len = buffer.len();

    match key {
        CipherKey::Aes256(key) => Encryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|_| "Failed to create AES-256 encryptor")?
            .encrypt_padded_mut::<NoPadding>(buffer, plain_len)
            .map_err(|_| "Encryption failed"),
        CipherKey::Aes128(key) => Encryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| "Failed to create AES-128 encryptor")?
            .encrypt_padded_mut::<NoPadding>(buffer, plain_len)
            .map_err(|_| "Encryption failed"),
    }
}

fn hexsum(data: &[u8], size: usize) -> Vec<u8, 4> {
    let sum: u32 = data.iter().map(|&b| u32::from(b)).sum();
    let bytes = sum.to_be_bytes();
    let count = size.min(bytes.len());

    let mut result = Vec::<u8, 4>::new();
    let start = bytes.len() - count;
    let _ = result.extend_from_slice(&bytes[start..]);
    result
}
