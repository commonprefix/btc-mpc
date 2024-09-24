use base64::prelude::*;
use eyre::Result;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

pub type ShareIndex = u16;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PartialSignature {
    pub index: ShareIndex,
    pub value: G1Element,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub sigs: Vec<PartialSignature>,
}

const G1_ELEMENT_BYTE_LENGTH: usize = 48;
const SCALAR_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct G1Element {
    pub bytes: Vec<u8>, // TODO: Use G1_ELEMENT_BYTE_LENGTH
}

#[derive(Debug, Clone, PartialEq)]
pub struct Scalar {
    pub bytes: Vec<u8>,
}

impl Serialize for G1Element {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = BASE64_STANDARD.encode(&self.bytes);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for G1Element {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = BASE64_STANDARD.decode(&s).map_err(D::Error::custom)?;
        if decoded.len() != G1_ELEMENT_BYTE_LENGTH {
            return Err(D::Error::custom(format!(
                "Invalid length for G1Element: expected {}, got {}",
                G1_ELEMENT_BYTE_LENGTH,
                decoded.len()
            )));
        }
        Ok(G1Element { bytes: decoded })
    }
}

impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = BASE64_STANDARD.encode(&self.bytes);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = BASE64_STANDARD.decode(&s).map_err(D::Error::custom)?;
        if decoded.len() != SCALAR_LENGTH {
            return Err(D::Error::custom(format!(
                "Invalid length for Scalar: expected {}, got {}",
                SCALAR_LENGTH,
                decoded.len()
            )));
        }
        Ok(Scalar { bytes: decoded })
    }
}
