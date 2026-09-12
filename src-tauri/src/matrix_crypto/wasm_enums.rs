//! The numeric values matrix-sdk-crypto-wasm's enums cross the IPC boundary as.

use matrix_sdk_crypto::types::EventEncryptionAlgorithm;

/// wasm's `RequestType`.
pub mod request_type {
    pub const KEYS_UPLOAD: u8 = 0;
    pub const KEYS_QUERY: u8 = 1;
    pub const KEYS_CLAIM: u8 = 2;
    pub const TO_DEVICE: u8 = 3;
    pub const SIGNATURE_UPLOAD: u8 = 4;
    pub const ROOM_MESSAGE: u8 = 5;
    pub const KEYS_BACKUP: u8 = 6;
}

/// wasm's `ProcessedToDeviceEventType`.
pub mod processed_to_device_event_type {
    pub const DECRYPTED: u8 = 0;
    pub const UNABLE_TO_DECRYPT: u8 = 1;
    pub const PLAIN_TEXT: u8 = 2;
    pub const INVALID: u8 = 3;
}

/// wasm's `EncryptionAlgorithm`; anything the bindings do not name maps to `Unknown`.
pub fn encryption_algorithm(algorithm: &EventEncryptionAlgorithm) -> u8 {
    match algorithm {
        EventEncryptionAlgorithm::OlmV1Curve25519AesSha2 => 0,
        EventEncryptionAlgorithm::MegolmV1AesSha2 => 1,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_type_codes_match_the_wasm_enum() {
        assert_eq!(request_type::KEYS_UPLOAD, 0);
        assert_eq!(request_type::KEYS_QUERY, 1);
        assert_eq!(request_type::KEYS_CLAIM, 2);
        assert_eq!(request_type::TO_DEVICE, 3);
        assert_eq!(request_type::SIGNATURE_UPLOAD, 4);
        assert_eq!(request_type::ROOM_MESSAGE, 5);
        assert_eq!(request_type::KEYS_BACKUP, 6);
    }

    #[test]
    fn processed_to_device_event_codes_match_the_wasm_enum() {
        assert_eq!(processed_to_device_event_type::DECRYPTED, 0);
        assert_eq!(processed_to_device_event_type::UNABLE_TO_DECRYPT, 1);
        assert_eq!(processed_to_device_event_type::PLAIN_TEXT, 2);
        assert_eq!(processed_to_device_event_type::INVALID, 3);
    }

    #[test]
    fn encryption_algorithm_codes_match_the_wasm_enum() {
        assert_eq!(
            encryption_algorithm(&EventEncryptionAlgorithm::OlmV1Curve25519AesSha2),
            0
        );
        assert_eq!(
            encryption_algorithm(&EventEncryptionAlgorithm::MegolmV1AesSha2),
            1
        );
        assert_eq!(
            encryption_algorithm(&EventEncryptionAlgorithm::from("m.some.future.algorithm")),
            2
        );
    }
}
