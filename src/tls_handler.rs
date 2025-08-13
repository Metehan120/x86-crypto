#[cfg(feature = "dev-logs")]
use log::trace;
use log::{debug, info};
#[cfg(not(feature = "experimental_tls_decryption"))]
use rustls::crypto::cipher::InboundPlainMessage;
use rustls::{
    ContentType, ProtocolVersion,
    crypto::cipher::{
        self, InboundOpaqueMessage, Iv, MessageDecrypter, MessageEncrypter, OutboundOpaqueMessage,
        PrefixedPayload,
    },
};

use crate::{
    ciphers::aes_cipher::{Aes256, AesError, Nonce},
    memory::zeroize::Zeroizeable,
};

pub struct AesGcmMessageHandler {
    cipher: Aes256,
    iv: cipher::Iv,
}

fn content_type_to_u8(t: ContentType) -> u8 {
    match t {
        ContentType::ChangeCipherSpec => 20,
        ContentType::Alert => 21,
        ContentType::Handshake => 22,
        ContentType::ApplicationData => 23,
        ContentType::Heartbeat => 24,
        _ => 24,
    }
}

fn protocol_version_to_u16(v: ProtocolVersion) -> u16 {
    match v {
        ProtocolVersion::SSLv3 => 0x0300,
        ProtocolVersion::TLSv1_0 => 0x0301,
        ProtocolVersion::TLSv1_1 => 0x0302,
        ProtocolVersion::TLSv1_2 => 0x0303,
        ProtocolVersion::TLSv1_3 => 0x0303,
        _ => 0x0303,
    }
}

impl AesGcmMessageHandler {
    pub fn new(iv: [u8; 12], key: &[u8]) -> Result<Self, AesError> {
        Ok(Self {
            cipher: Aes256::new(&key)?,
            iv: Iv::copy(&iv),
        })
    }

    fn make_nonce(iv: &Iv, seq: u64) -> [u8; 12] {
        let mut nonce: [u8; 12] = iv.as_ref().try_into().expect("Iv must be 12 bytes");
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }

    fn make_aad(typ: u8, version: u16, payload_len: usize) -> [u8; 5] {
        let mut aad = [0u8; 5];
        aad[0] = typ;
        aad[1..3].copy_from_slice(&version.to_be_bytes());
        aad[3..5].copy_from_slice(&(payload_len as u16).to_be_bytes());
        aad
    }
}

impl MessageEncrypter for AesGcmMessageHandler {
    fn encrypt(
        &mut self,
        msg: cipher::OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<cipher::OutboundOpaqueMessage, rustls::Error> {
        #[cfg(feature = "audit-logs")]
        info!("Starting TLS Encryption");

        let nonce = Self::make_nonce(&self.iv, seq);
        let aad = Self::make_aad(
            content_type_to_u8(msg.typ),
            protocol_version_to_u16(msg.version),
            msg.payload.len(),
        );

        let nonce = Nonce::from_bytes(nonce);
        let mut payload = msg.payload.to_vec();

        #[cfg(feature = "dev-logs")]
        trace!("Nonce Succesfully generated");

        #[cfg(feature = "audit-logs")]
        debug!("Starting AES-GCM encryption");

        let ciphertext = self
            .cipher
            .encrypt_inplace_with_aad(&mut payload, nonce, &aad);

        payload.extend_from_slice(
            ciphertext
                .map_err(|_| rustls::Error::DecryptError)?
                .as_bytes(),
        );

        let mut output = PrefixedPayload::with_capacity(payload.len());
        output.extend_from_slice(&payload);
        payload.zeroize();

        #[cfg(feature = "audit-logs")]
        info!("TLS encryption Successful");

        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, output))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 16
    }
}

#[cfg(not(feature = "experimental_tls_decryption"))]
impl MessageDecrypter for AesGcmMessageHandler {
    fn decrypt<'a>(
        &mut self,
        _: InboundOpaqueMessage<'a>,
        _: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        use log::error;

        error!("Attempted to decrypt without enabling 'experimental_tls_decryption' feature.");
        unimplemented!("AES Decryption is not enabled");
    }
}

#[cfg(feature = "experimental_tls_decryption")]
impl MessageDecrypter for AesGcmMessageHandler {
    fn decrypt<'a>(
        &mut self,
        msg: cipher::InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<cipher::InboundPlainMessage<'a>, rustls::Error> {
        use log::{debug, trace, warn};

        warn!("TLS DECRYPTION IS EXPERIMENTAL USE CAREFULLY");
        warn!("TLS DECRYPTION WILL MEMORY LEAK");
        warn!("ZEROIZE DATA AFTER USE");

        warn!("TSL Decryption Starting");

        let nonce = Self::make_nonce(&self.iv, seq);
        let aad = Self::make_aad(
            content_type_to_u8(msg.typ),
            protocol_version_to_u16(msg.version),
            msg.payload.len() - 16,
        );

        let nonce = Nonce::from_bytes(nonce);

        #[cfg(feature = "dev-logs")]
        trace!("Nonce Succesfully generated");

        let len = msg.payload.len();
        if len < 16 {
            return Err(rustls::Error::DecryptError);
        }

        debug!("Starting AES-GCM decryption");

        let output = self
            .cipher
            .decrypt_with_aad(&mut msg.payload.to_vec(), nonce, &aad)
            .map_err(|_| rustls::Error::DecryptError)?;

        #[cfg(feature = "audit-logs")]
        warn!("⚠️ Memory leak: TLS decrypted message leaked for lifetime compatibility");
        let leaked: &'a mut [u8] = Box::leak(output.into_boxed_slice());

        let message = InboundOpaqueMessage::new(msg.typ, msg.version, leaked).into_plain_message();

        warn!("TLS Decryption Successful");

        Ok(message)
    }
}
