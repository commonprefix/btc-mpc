use core::fmt;
use std::collections::HashMap;

use base64::prelude::*;
use eyre::{eyre, Result};
use serde::{
    de::{self, Error, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};

pub const DST_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd)]
pub enum Phase {
    Phase1,
    Phase2,
    Phase3,
    Phase4,
}

pub type ShareIndex = u16;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PartialSignature {
    pub index: ShareIndex,
    pub value: G1Element,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGSession {
    pub phase: Phase,
    pub threshold: u16,
    pub nodes: Nodes,
    pub messages: Vec<Message>,
    pub confirmations: Vec<Confirmation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigningSession {
    pub session_id: String,
    pub nodes: Nodes,
    pub sigs: HashMap<PartyId, Vec<PartialSignature>>,
    pub payload: Vec<u8>,
}

const G1_ELEMENT_BYTE_LENGTH: usize = 48;
const PROJECTIVE_POINT_BYTE_LENGTH: usize = 33;
const SCALAR_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct ProjectivePoint {
    pub bytes: Vec<u8>, // TODO: Use PROJECTIVE_POINT_BYTE_LENGTH
}

#[derive(Debug, Clone, PartialEq)]
pub struct G1Element {
    pub bytes: Vec<u8>, // TODO: Use G1_ELEMENT_BYTE_LENGTH
}

pub type PartyId = u16;

pub type PublicPoly = Vec<ProjectivePoint>;
#[derive(Debug, Clone, PartialEq)]
pub struct Scalar {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DLNizk {
    pub A: ProjectivePoint,
    pub z: Scalar,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MultiRecipientEncryption {
    pub r_g: ProjectivePoint,
    pub encs: Vec<Vec<u8>>,
    pub nizk: DLNizk,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: PartyId,
    pub pk: ProjectivePoint,
    pub weight: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Nodes {
    pub nodes: Vec<Node>,
    pub total_weight: u16,
    pub accumulated_weights: Vec<u16>,
    pub nodes_with_nonzero_weight: Vec<u16>,
}

impl Nodes {
    const MAX_NODES: usize = 1000;

    pub fn new(nodes: Vec<Node>) -> Result<Self> {
        let mut nodes = nodes;
        nodes.sort_by_key(|n| n.id);
        // Check all ids are consecutive and start from 0
        if (0..nodes.len()).any(|i| (nodes[i].id as usize) != i) {
            return Err(eyre!("InvalidInput"));
        }
        // Make sure we never overflow in the functions below.
        if nodes.is_empty() || nodes.len() > Self::MAX_NODES {
            return Err(eyre!("InvalidInput"));
        }
        // Make sure we never overflow in the functions below, as we don't expect to have more than u16::MAX total weight.
        let total_weight = nodes.iter().map(|n| n.weight as u32).sum::<u32>();
        if total_weight > u16::MAX as u32 || total_weight == 0 {
            return Err(eyre!("InvalidInput"));
        }
        let total_weight = total_weight as u16;

        // We use the next two to map share ids to party ids.
        let accumulated_weights = Self::get_accumulated_weights(&nodes);
        let nodes_with_nonzero_weight = Self::filter_nonzero_weights(&nodes);

        Ok(Self {
            nodes,
            total_weight,
            accumulated_weights,
            nodes_with_nonzero_weight,
        })
    }

    fn get_accumulated_weights(nodes: &[Node]) -> Vec<u16> {
        nodes
            .iter()
            .filter_map(|n| if n.weight > 0 { Some(n.weight) } else { None })
            .scan(0, |accumulated_weight, weight| {
                *accumulated_weight += weight;
                Some(*accumulated_weight)
            })
            .collect::<Vec<_>>()
    }

    fn filter_nonzero_weights(nodes: &[Node]) -> Vec<u16> {
        nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| if n.weight > 0 { Some(i as u16) } else { None })
            .collect::<Vec<_>>()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub sender: PartyId,
    pub vss_pk: PublicPoly,
    pub encrypted_shares: MultiRecipientEncryption,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DdhTupleNizk {
    pub A: ProjectivePoint,
    pub B: ProjectivePoint,
    pub z: Scalar,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryPackage {
    pub ephemeral_key: ProjectivePoint,
    pub proof: DdhTupleNizk,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Complaint {
    pub accused_sender: PartyId,
    pub proof: RecoveryPackage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Confirmation {
    pub sender: PartyId,
    /// List of complaints against other parties. Empty if there are none.
    pub complaints: Vec<Complaint>,
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
        match decoded.len() {
            G1_ELEMENT_BYTE_LENGTH => Ok(G1Element { bytes: decoded }),
            len => Err(D::Error::custom(
                format_args!(
                    "Invalid length for G1Element: expected {}, got {}",
                    G1_ELEMENT_BYTE_LENGTH, len
                )
                .to_string(),
            )),
        }
    }
}

impl Serialize for ProjectivePoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = BASE64_STANDARD.encode(&self.bytes);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for ProjectivePoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = BASE64_STANDARD.decode(&s).map_err(D::Error::custom)?;
        match decoded.len() {
            PROJECTIVE_POINT_BYTE_LENGTH => Ok(ProjectivePoint { bytes: decoded }),
            len => Err(D::Error::custom(
                format_args!(
                    "Invalid length for ProjectivePoint: expected {}, got {}",
                    PROJECTIVE_POINT_BYTE_LENGTH, len
                )
                .to_string(),
            )),
        }
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
        match decoded.len() {
            SCALAR_LENGTH => Ok(Scalar { bytes: decoded }),
            len => Err(D::Error::custom(
                format!(
                    "Invalid length for Scalar: expected {}, got {}",
                    SCALAR_LENGTH, len
                )
                .to_string(),
            )),
        }
    }
}

impl Serialize for DdhTupleNizk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(3)?; // The number of fields in the struct
        tuple.serialize_element(&self.A)?;
        tuple.serialize_element(&self.B)?;
        tuple.serialize_element(&self.z)?;
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for DdhTupleNizk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DdhTupleNizkVisitor;

        impl<'de> Visitor<'de> for DdhTupleNizkVisitor {
            type Value = DdhTupleNizk;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a tuple of (A, B, z)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<DdhTupleNizk, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let A = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let B = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let z = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                Ok(DdhTupleNizk { A, B, z })
            }
        }

        deserializer.deserialize_tuple(3, DdhTupleNizkVisitor)
    }
}

impl Serialize for DLNizk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&self.A)?;
        tuple.serialize_element(&self.z)?;
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for DLNizk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DLNizkVisitor;

        impl<'de> Visitor<'de> for DLNizkVisitor {
            type Value = DLNizk;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a tuple of (A, z)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<DLNizk, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let A = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let z = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                Ok(DLNizk { A, z })
            }
        }

        deserializer.deserialize_tuple(2, DLNizkVisitor)
    }
}

impl Serialize for MultiRecipientEncryption {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(3)?; // The number of fields in the struct
        tuple.serialize_element(&self.r_g)?;
        tuple.serialize_element(&self.encs)?;
        tuple.serialize_element(&self.nizk)?;
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for MultiRecipientEncryption {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MultiRecipientEncryptionVisitor;

        impl<'de> Visitor<'de> for MultiRecipientEncryptionVisitor {
            type Value = MultiRecipientEncryption;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a tuple of (r_g, encs, nizk)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<MultiRecipientEncryption, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let r_g = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let encs = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let nizk = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                Ok(MultiRecipientEncryption { r_g, encs, nizk })
            }
        }

        deserializer.deserialize_tuple(3, MultiRecipientEncryptionVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::dkg::{
        Complaint, Confirmation, DKGSession, DLNizk, DdhTupleNizk, Message,
        MultiRecipientEncryption, Phase, ProjectivePoint, RecoveryPackage, Scalar,
    };
    use serde_json;

    use super::{Node, Nodes};

    #[test]
    fn nodes_serialization() {
        let expected_json = r#"{
            "nodes": [
                {
                    "id": 0,
                    "pk": "A74EgulkcNv8eBokNDvpeOE9Bu+dJiEyTOzPLkba7Uvj",
                    "weight": 1
                },
                {
                    "id": 1,
                    "pk": "A9Is2Ab9dqd/Vl/HY3jb6RnAbL+IjpQI32n+K45Gtw2b",
                    "weight": 2
                },
                {
                    "id": 2,
                    "pk": "A8exeyyN+cgrb40Z6WrU+Hmm5TqePy2G7sbAegAGZiuw",
                    "weight": 3
                },
                {
                    "id": 3,
                    "pk": "A9kRuamZuE+O8NT+sXIEX0Ts/lhLIMTtieXgA0KbD14M",
                    "weight": 4
                },
                {
                    "id": 4,
                    "pk": "A5tpx9G2V7FFWStFkeXz+nfimarbOLLJOiXW2gYvXnZO",
                    "weight": 5
                }
            ],
            "total_weight": 15,
            "accumulated_weights": [
                1,
                3,
                6,
                10,
                15
            ],
            "nodes_with_nonzero_weight": [
                0,
                1,
                2,
                3,
                4
            ]
        }"#
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();

        let expected_nodes = Nodes {
            nodes: vec![
                Node {
                    id: 0,
                    pk: ProjectivePoint {
                        bytes: vec![
                            3, 190, 4, 130, 233, 100, 112, 219, 252, 120, 26, 36, 52, 59, 233, 120,
                            225, 61, 6, 239, 157, 38, 33, 50, 76, 236, 207, 46, 70, 218, 237, 75,
                            227,
                        ],
                    },
                    weight: 1,
                },
                Node {
                    id: 1,
                    pk: ProjectivePoint {
                        bytes: vec![
                            3, 210, 44, 216, 6, 253, 118, 167, 127, 86, 95, 199, 99, 120, 219, 233,
                            25, 192, 108, 191, 136, 142, 148, 8, 223, 105, 254, 43, 142, 70, 183,
                            13, 155,
                        ],
                    },
                    weight: 2,
                },
                Node {
                    id: 2,
                    pk: ProjectivePoint {
                        bytes: vec![
                            3, 199, 177, 123, 44, 141, 249, 200, 43, 111, 141, 25, 233, 106, 212,
                            248, 121, 166, 229, 58, 158, 63, 45, 134, 238, 198, 192, 122, 0, 6,
                            102, 43, 176,
                        ],
                    },
                    weight: 3,
                },
                Node {
                    id: 3,
                    pk: ProjectivePoint {
                        bytes: vec![
                            3, 217, 17, 185, 169, 153, 184, 79, 142, 240, 212, 254, 177, 114, 4,
                            95, 68, 236, 254, 88, 75, 32, 196, 237, 137, 229, 224, 3, 66, 155, 15,
                            94, 12,
                        ],
                    },
                    weight: 4,
                },
                Node {
                    id: 4,
                    pk: ProjectivePoint {
                        bytes: vec![
                            3, 155, 105, 199, 209, 182, 87, 177, 69, 89, 43, 69, 145, 229, 243,
                            250, 119, 226, 153, 170, 219, 56, 178, 201, 58, 37, 214, 218, 6, 47,
                            94, 118, 78,
                        ],
                    },
                    weight: 5,
                },
            ],
            total_weight: 15,
            accumulated_weights: vec![1, 3, 6, 10, 15],
            nodes_with_nonzero_weight: vec![0, 1, 2, 3, 4],
        };

        let deserialized: Nodes = serde_json::from_str(&expected_json).unwrap();
        assert_eq!(expected_nodes, deserialized);

        let serialized = serde_json::to_string(&expected_nodes).unwrap();
        assert_eq!(expected_json.as_str(), serialized);
    }

    #[test]
    fn message_serialization() {
        let expected_json = r#"{
            "sender": 2,
            "vss_pk": [
                "A/7qHYlnteq4Kkv5YncPDzIcSzCkdorQk76T8xYyNqdz",
                "A5pS3aUksUfXtMGdGzBz4EiR7i+CgjzC4bVaeWXqoyhM",
                "A9z6jASldrHdQgcK91fBfBckUjRiE5e0RIkPAxx5pfUr",
                "Amfa3Osy5ulPd8qaBVfh9tsVmUHVwEWGkLyVUFmxVaht",
                "AqFp4lsUCHwyGjgeueOXULcf+3bi4xVfLtthmiA28bxz"
            ],
            "encrypted_shares": [
                "ArGeqPRMGN0pxToBPpnMEB2D13FfeenF3oVtc8QUqFfd",
                [
                [
                    169,
                    162,
                    153,
                    160,
                    152,
                    214,
                    74,
                    21,
                    239,
                    148,
                    16,
                    253,
                    248,
                    110,
                    87,
                    133,
                    188,
                    88,
                    20,
                    94,
                    125,
                    172,
                    17,
                    17,
                    14,
                    21,
                    139,
                    49,
                    242,
                    205,
                    174,
                    19,
                    234
                ],
                [
                    133,
                    56,
                    168,
                    214,
                    186,
                    73,
                    13,
                    250,
                    145,
                    100,
                    229,
                    249,
                    81,
                    64,
                    161,
                    131,
                    60,
                    157,
                    85,
                    4,
                    65,
                    232,
                    64,
                    161,
                    219,
                    86,
                    253,
                    33,
                    202,
                    109,
                    240,
                    203,
                    88,
                    90,
                    112,
                    77,
                    171,
                    180,
                    145,
                    70,
                    82,
                    137,
                    236,
                    211,
                    15,
                    181,
                    214,
                    68,
                    252,
                    136,
                    167,
                    116,
                    23,
                    140,
                    81,
                    149,
                    127,
                    234,
                    145,
                    92,
                    230,
                    246,
                    86,
                    163,
                    181
                ],
                [
                    76,
                    235,
                    251,
                    92,
                    111,
                    240,
                    226,
                    8,
                    168,
                    95,
                    18,
                    73,
                    128,
                    50,
                    17,
                    64,
                    198,
                    66,
                    63,
                    113,
                    164,
                    222,
                    155,
                    198,
                    169,
                    192,
                    45,
                    23,
                    22,
                    181,
                    152,
                    79,
                    32,
                    111,
                    162,
                    121,
                    210,
                    98,
                    245,
                    86,
                    195,
                    119,
                    253,
                    8,
                    16,
                    28,
                    36,
                    238,
                    119,
                    139,
                    83,
                    50,
                    55,
                    215,
                    121,
                    69,
                    186,
                    209,
                    215,
                    30,
                    228,
                    121,
                    234,
                    169,
                    56,
                    214,
                    8,
                    234,
                    253,
                    43,
                    223,
                    221,
                    232,
                    7,
                    188,
                    194,
                    109,
                    204,
                    111,
                    225,
                    169,
                    102,
                    45,
                    58,
                    84,
                    224,
                    185,
                    9,
                    203,
                    30,
                    168,
                    41,
                    82,
                    45,
                    69,
                    7,
                    217
                ],
                [
                    8,
                    144,
                    33,
                    126,
                    121,
                    248,
                    255,
                    24,
                    201,
                    30,
                    8,
                    53,
                    98,
                    173,
                    189,
                    44,
                    140,
                    188,
                    24,
                    253,
                    147,
                    111,
                    218,
                    66,
                    71,
                    150,
                    145,
                    241,
                    38,
                    194,
                    209,
                    51,
                    1,
                    11,
                    242,
                    232,
                    206,
                    73,
                    152,
                    187,
                    170,
                    11,
                    101,
                    29,
                    208,
                    157,
                    152,
                    93,
                    208,
                    158,
                    149,
                    42,
                    253,
                    129,
                    156,
                    119,
                    188,
                    154,
                    26,
                    211,
                    109,
                    43,
                    247,
                    94,
                    95,
                    175,
                    39,
                    215,
                    144,
                    111,
                    143,
                    31,
                    110,
                    98,
                    2,
                    147,
                    186,
                    254,
                    202,
                    117,
                    81,
                    235,
                    196,
                    254,
                    2,
                    82,
                    219,
                    219,
                    113,
                    73,
                    115,
                    110,
                    248,
                    251,
                    39,
                    150,
                    147,
                    93,
                    2,
                    148,
                    36,
                    188,
                    108,
                    255,
                    63,
                    100,
                    16,
                    76,
                    119,
                    219,
                    25,
                    60,
                    140,
                    148,
                    129,
                    11,
                    44,
                    183,
                    141,
                    141,
                    225,
                    117,
                    82,
                    152,
                    55,
                    232,
                    217,
                    164,
                    108
                ],
                [
                    160,
                    75,
                    230,
                    160,
                    17,
                    245,
                    152,
                    123,
                    28,
                    97,
                    227,
                    133,
                    69,
                    40,
                    21,
                    57,
                    5,
                    41,
                    154,
                    225,
                    52,
                    181,
                    208,
                    241,
                    182,
                    60,
                    161,
                    239,
                    251,
                    90,
                    84,
                    238,
                    10,
                    56,
                    44,
                    203,
                    24,
                    92,
                    133,
                    101,
                    39,
                    195,
                    224,
                    231,
                    60,
                    26,
                    181,
                    58,
                    152,
                    36,
                    106,
                    79,
                    163,
                    93,
                    234,
                    87,
                    226,
                    162,
                    205,
                    78,
                    9,
                    182,
                    252,
                    95,
                    146,
                    224,
                    48,
                    47,
                    135,
                    214,
                    5,
                    106,
                    178,
                    12,
                    246,
                    75,
                    216,
                    22,
                    179,
                    202,
                    3,
                    72,
                    190,
                    81,
                    234,
                    121,
                    45,
                    164,
                    187,
                    162,
                    153,
                    220,
                    194,
                    88,
                    241,
                    162,
                    55,
                    166,
                    211,
                    232,
                    185,
                    6,
                    234,
                    159,
                    207,
                    238,
                    14,
                    220,
                    249,
                    223,
                    181,
                    139,
                    75,
                    13,
                    245,
                    199,
                    181,
                    88,
                    13,
                    208,
                    202,
                    42,
                    94,
                    236,
                    61,
                    165,
                    210,
                    86,
                    119,
                    86,
                    130,
                    150,
                    102,
                    115,
                    109,
                    157,
                    195,
                    37,
                    16,
                    31,
                    206,
                    23,
                    253,
                    100,
                    88,
                    240,
                    30,
                    233,
                    80,
                    220,
                    132,
                    98,
                    31,
                    137,
                    141,
                    120,
                    68,
                    250,
                    74,
                    247,
                    94
                ]
                ],
                [
                "AvGpLk/mLvuSbUzCe+KCKeupTTocEE9S9hZX15HsE4Wa",
                "Vvct1q/KniCLujurtGhQmbV6Gq3MvMMoJcZvHPZVFSs="
                ]
            ]
        }"#
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();

        let expected_message = Message {
            encrypted_shares: MultiRecipientEncryption {
                r_g: ProjectivePoint {
                    bytes: vec![
                        2, 177, 158, 168, 244, 76, 24, 221, 41, 197, 58, 1, 62, 153, 204, 16, 29,
                        131, 215, 113, 95, 121, 233, 197, 222, 133, 109, 115, 196, 20, 168, 87,
                        221,
                    ],
                },
                encs: vec![
                    vec![
                        169, 162, 153, 160, 152, 214, 74, 21, 239, 148, 16, 253, 248, 110, 87, 133,
                        188, 88, 20, 94, 125, 172, 17, 17, 14, 21, 139, 49, 242, 205, 174, 19, 234,
                    ],
                    vec![
                        133, 56, 168, 214, 186, 73, 13, 250, 145, 100, 229, 249, 81, 64, 161, 131,
                        60, 157, 85, 4, 65, 232, 64, 161, 219, 86, 253, 33, 202, 109, 240, 203, 88,
                        90, 112, 77, 171, 180, 145, 70, 82, 137, 236, 211, 15, 181, 214, 68, 252,
                        136, 167, 116, 23, 140, 81, 149, 127, 234, 145, 92, 230, 246, 86, 163, 181,
                    ],
                    vec![
                        76, 235, 251, 92, 111, 240, 226, 8, 168, 95, 18, 73, 128, 50, 17, 64, 198,
                        66, 63, 113, 164, 222, 155, 198, 169, 192, 45, 23, 22, 181, 152, 79, 32,
                        111, 162, 121, 210, 98, 245, 86, 195, 119, 253, 8, 16, 28, 36, 238, 119,
                        139, 83, 50, 55, 215, 121, 69, 186, 209, 215, 30, 228, 121, 234, 169, 56,
                        214, 8, 234, 253, 43, 223, 221, 232, 7, 188, 194, 109, 204, 111, 225, 169,
                        102, 45, 58, 84, 224, 185, 9, 203, 30, 168, 41, 82, 45, 69, 7, 217,
                    ],
                    vec![
                        8, 144, 33, 126, 121, 248, 255, 24, 201, 30, 8, 53, 98, 173, 189, 44, 140,
                        188, 24, 253, 147, 111, 218, 66, 71, 150, 145, 241, 38, 194, 209, 51, 1,
                        11, 242, 232, 206, 73, 152, 187, 170, 11, 101, 29, 208, 157, 152, 93, 208,
                        158, 149, 42, 253, 129, 156, 119, 188, 154, 26, 211, 109, 43, 247, 94, 95,
                        175, 39, 215, 144, 111, 143, 31, 110, 98, 2, 147, 186, 254, 202, 117, 81,
                        235, 196, 254, 2, 82, 219, 219, 113, 73, 115, 110, 248, 251, 39, 150, 147,
                        93, 2, 148, 36, 188, 108, 255, 63, 100, 16, 76, 119, 219, 25, 60, 140, 148,
                        129, 11, 44, 183, 141, 141, 225, 117, 82, 152, 55, 232, 217, 164, 108,
                    ],
                    vec![
                        160, 75, 230, 160, 17, 245, 152, 123, 28, 97, 227, 133, 69, 40, 21, 57, 5,
                        41, 154, 225, 52, 181, 208, 241, 182, 60, 161, 239, 251, 90, 84, 238, 10,
                        56, 44, 203, 24, 92, 133, 101, 39, 195, 224, 231, 60, 26, 181, 58, 152, 36,
                        106, 79, 163, 93, 234, 87, 226, 162, 205, 78, 9, 182, 252, 95, 146, 224,
                        48, 47, 135, 214, 5, 106, 178, 12, 246, 75, 216, 22, 179, 202, 3, 72, 190,
                        81, 234, 121, 45, 164, 187, 162, 153, 220, 194, 88, 241, 162, 55, 166, 211,
                        232, 185, 6, 234, 159, 207, 238, 14, 220, 249, 223, 181, 139, 75, 13, 245,
                        199, 181, 88, 13, 208, 202, 42, 94, 236, 61, 165, 210, 86, 119, 86, 130,
                        150, 102, 115, 109, 157, 195, 37, 16, 31, 206, 23, 253, 100, 88, 240, 30,
                        233, 80, 220, 132, 98, 31, 137, 141, 120, 68, 250, 74, 247, 94,
                    ],
                ],
                nizk: DLNizk {
                    A: ProjectivePoint {
                        bytes: vec![
                            2, 241, 169, 46, 79, 230, 46, 251, 146, 109, 76, 194, 123, 226, 130,
                            41, 235, 169, 77, 58, 28, 16, 79, 82, 246, 22, 87, 215, 145, 236, 19,
                            133, 154,
                        ],
                    },
                    z: Scalar {
                        bytes: vec![
                            86, 247, 45, 214, 175, 202, 158, 32, 139, 186, 59, 171, 180, 104, 80,
                            153, 181, 122, 26, 173, 204, 188, 195, 40, 37, 198, 111, 28, 246, 85,
                            21, 43,
                        ],
                    },
                },
            },
            sender: 2,
            vss_pk: vec![
                ProjectivePoint {
                    bytes: vec![
                        3, 254, 234, 29, 137, 103, 181, 234, 184, 42, 75, 249, 98, 119, 15, 15, 50,
                        28, 75, 48, 164, 118, 138, 208, 147, 190, 147, 243, 22, 50, 54, 167, 115,
                    ],
                },
                ProjectivePoint {
                    bytes: vec![
                        3, 154, 82, 221, 165, 36, 177, 71, 215, 180, 193, 157, 27, 48, 115, 224,
                        72, 145, 238, 47, 130, 130, 60, 194, 225, 181, 90, 121, 101, 234, 163, 40,
                        76,
                    ],
                },
                ProjectivePoint {
                    bytes: vec![
                        3, 220, 250, 140, 4, 165, 118, 177, 221, 66, 7, 10, 247, 87, 193, 124, 23,
                        36, 82, 52, 98, 19, 151, 180, 68, 137, 15, 3, 28, 121, 165, 245, 43,
                    ],
                },
                ProjectivePoint {
                    bytes: vec![
                        2, 103, 218, 220, 235, 50, 230, 233, 79, 119, 202, 154, 5, 87, 225, 246,
                        219, 21, 153, 65, 213, 192, 69, 134, 144, 188, 149, 80, 89, 177, 85, 168,
                        109,
                    ],
                },
                ProjectivePoint {
                    bytes: vec![
                        2, 161, 105, 226, 91, 20, 8, 124, 50, 26, 56, 30, 185, 227, 151, 80, 183,
                        31, 251, 118, 226, 227, 21, 95, 46, 219, 97, 154, 32, 54, 241, 188, 115,
                    ],
                },
            ],
        };

        let deserialized: Message = serde_json::from_str(&expected_json).unwrap();
        assert_eq!(expected_message, deserialized);

        let serialized = serde_json::to_string(&expected_message).unwrap();
        assert_eq!(expected_json.as_str(), serialized);
    }

    #[test]
    fn confirmation_serialization() {
        let expected_json = r#"{
            "sender": 0,
            "complaints": [{
                "accused_sender": 1,
                "proof": {
                    "ephemeral_key": "AqFp4lsUCHwyGjgeueOXULcf+3bi4xVfLtthmiA28bxz",
                    "proof": [
                        "AqFp4lsUCHwyGjgeueOXULcf+3bi4xVfLtthmiA28bxz",
                        "AqFp4lsUCHwyGjgeueOXULcf+3bi4xVfLtthmiA28bxz",
                        "Q2/haZnSPsxTMc2xk4mP3hfBhYy1YXVoFbpqE71iaME="
                    ]
                }
            }]
        }"#
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();

        let expected_confirmation = Confirmation {
            sender: 0,
            complaints: vec![Complaint {
                accused_sender: 1,
                proof: RecoveryPackage {
                    ephemeral_key: ProjectivePoint {
                        bytes: vec![
                            2, 161, 105, 226, 91, 20, 8, 124, 50, 26, 56, 30, 185, 227, 151, 80,
                            183, 31, 251, 118, 226, 227, 21, 95, 46, 219, 97, 154, 32, 54, 241,
                            188, 115,
                        ],
                    },
                    proof: DdhTupleNizk {
                        A: ProjectivePoint {
                            bytes: vec![
                                2, 161, 105, 226, 91, 20, 8, 124, 50, 26, 56, 30, 185, 227, 151,
                                80, 183, 31, 251, 118, 226, 227, 21, 95, 46, 219, 97, 154, 32, 54,
                                241, 188, 115,
                            ],
                        },
                        B: ProjectivePoint {
                            bytes: vec![
                                2, 161, 105, 226, 91, 20, 8, 124, 50, 26, 56, 30, 185, 227, 151,
                                80, 183, 31, 251, 118, 226, 227, 21, 95, 46, 219, 97, 154, 32, 54,
                                241, 188, 115,
                            ],
                        },
                        z: Scalar {
                            bytes: vec![
                                67, 111, 225, 105, 153, 210, 62, 204, 83, 49, 205, 177, 147, 137,
                                143, 222, 23, 193, 133, 140, 181, 97, 117, 104, 21, 186, 106, 19,
                                189, 98, 104, 193,
                            ],
                        },
                    },
                },
            }],
        };

        let deserialized: Confirmation = serde_json::from_str(&expected_json).unwrap();
        assert_eq!(expected_confirmation, deserialized);

        let serialized = serde_json::to_string(&expected_confirmation).unwrap();
        assert_eq!(expected_json.as_str(), serialized);
    }

    #[test]
    fn session_serialization() {
        let expected_json = r#"{
            "phase": "Phase2",
            "threshold":5,
            "nodes": {
                "nodes": [
                    {
                        "id": 0,
                        "pk": "A74EgulkcNv8eBokNDvpeOE9Bu+dJiEyTOzPLkba7Uvj",
                        "weight": 1
                    },
                    {
                        "id": 1,
                        "pk": "A9Is2Ab9dqd/Vl/HY3jb6RnAbL+IjpQI32n+K45Gtw2b",
                        "weight": 2
                    },
                    {
                        "id": 2,
                        "pk": "A8exeyyN+cgrb40Z6WrU+Hmm5TqePy2G7sbAegAGZiuw",
                        "weight": 3
                    },
                    {
                        "id": 3,
                        "pk": "A9kRuamZuE+O8NT+sXIEX0Ts/lhLIMTtieXgA0KbD14M",
                        "weight": 4
                    },
                    {
                        "id": 4,
                        "pk": "A5tpx9G2V7FFWStFkeXz+nfimarbOLLJOiXW2gYvXnZO",
                        "weight": 5
                    }
                ],
                "total_weight": 15,
                "accumulated_weights": [
                    1,
                    3,
                    6,
                    10,
                    15
                ],
                "nodes_with_nonzero_weight": [
                    0,
                    1,
                    2,
                    3,
                    4
                ]
            },
            "messages":[],
            "confirmations":[]
        }"#
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
        let expected_session = DKGSession {
            phase: Phase::Phase2,
            threshold: 5,
            nodes: Nodes {
                nodes: vec![
                    Node {
                        id: 0,
                        pk: ProjectivePoint {
                            bytes: vec![
                                3, 190, 4, 130, 233, 100, 112, 219, 252, 120, 26, 36, 52, 59, 233,
                                120, 225, 61, 6, 239, 157, 38, 33, 50, 76, 236, 207, 46, 70, 218,
                                237, 75, 227,
                            ],
                        },
                        weight: 1,
                    },
                    Node {
                        id: 1,
                        pk: ProjectivePoint {
                            bytes: vec![
                                3, 210, 44, 216, 6, 253, 118, 167, 127, 86, 95, 199, 99, 120, 219,
                                233, 25, 192, 108, 191, 136, 142, 148, 8, 223, 105, 254, 43, 142,
                                70, 183, 13, 155,
                            ],
                        },
                        weight: 2,
                    },
                    Node {
                        id: 2,
                        pk: ProjectivePoint {
                            bytes: vec![
                                3, 199, 177, 123, 44, 141, 249, 200, 43, 111, 141, 25, 233, 106,
                                212, 248, 121, 166, 229, 58, 158, 63, 45, 134, 238, 198, 192, 122,
                                0, 6, 102, 43, 176,
                            ],
                        },
                        weight: 3,
                    },
                    Node {
                        id: 3,
                        pk: ProjectivePoint {
                            bytes: vec![
                                3, 217, 17, 185, 169, 153, 184, 79, 142, 240, 212, 254, 177, 114,
                                4, 95, 68, 236, 254, 88, 75, 32, 196, 237, 137, 229, 224, 3, 66,
                                155, 15, 94, 12,
                            ],
                        },
                        weight: 4,
                    },
                    Node {
                        id: 4,
                        pk: ProjectivePoint {
                            bytes: vec![
                                3, 155, 105, 199, 209, 182, 87, 177, 69, 89, 43, 69, 145, 229, 243,
                                250, 119, 226, 153, 170, 219, 56, 178, 201, 58, 37, 214, 218, 6,
                                47, 94, 118, 78,
                            ],
                        },
                        weight: 5,
                    },
                ],
                total_weight: 15,
                accumulated_weights: vec![1, 3, 6, 10, 15],
                nodes_with_nonzero_weight: vec![0, 1, 2, 3, 4],
            },
            messages: vec![],
            confirmations: vec![],
        };

        let deserialize: DKGSession = serde_json::from_str(&expected_json).unwrap();
        assert_eq!(expected_session, deserialize);

        let serialize = serde_json::to_string(&expected_session).unwrap();
        assert_eq!(expected_json.as_str(), serialize);
    }
}
