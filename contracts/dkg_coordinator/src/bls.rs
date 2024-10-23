use base64::prelude::*;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Session {
    pub threshold: u16,
    pub nodes: Nodes,
    pub messages: Vec<Message>,
    pub confirmations: Vec<Confirmation>,
}

const G2_ELEMENT_BYTE_LENGTH: usize = 96;
const SCALAR_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct G2Element(pub Vec<u8>); // TODO: Use G2_ELEMENT_BYTE_LENGTH

pub type PartyId = u16;

pub type PublicPoly = Vec<G2Element>;
#[derive(Debug, Clone, PartialEq)]
pub struct Scalar(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DLNizk(G2Element, Scalar);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiRecipientEncryption(G2Element, Vec<Vec<u8>>, DLNizk);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: PartyId,
    pub pk: G2Element,
    pub weight: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Nodes {
    pub nodes: Vec<Node>,
    pub total_weight: u16,
    pub accumulated_weights: Vec<u16>,
    pub nodes_with_nonzero_weight: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub sender: PartyId,
    pub vss_pk: PublicPoly,
    pub encrypted_shares: MultiRecipientEncryption,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DdhTupleNizk(G2Element, G2Element, Scalar);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryPackage {
    pub ephemeral_key: G2Element,
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

impl Serialize for G2Element {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = BASE64_STANDARD.encode(&self.0);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for G2Element {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = BASE64_STANDARD.decode(&s).map_err(D::Error::custom)?;
        match decoded.len() {
            G2_ELEMENT_BYTE_LENGTH => Ok(G2Element(decoded)),
            len => Err(D::Error::custom(
                format_args!(
                    "Invalid length for G2Element: expected {}, got {}",
                    G2_ELEMENT_BYTE_LENGTH, len
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
        let encoded = BASE64_STANDARD.encode(&self.0);
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
            SCALAR_LENGTH => Ok(Scalar(decoded)),
            len => Err(D::Error::custom(
                format_args!(
                    "Invalid length for Scalar: expected {}, got {}",
                    SCALAR_LENGTH, len
                )
                .to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::bls::{
        Complaint, Confirmation, DLNizk, DdhTupleNizk, G2Element, Message,
        MultiRecipientEncryption, RecoveryPackage, Scalar, Session,
    };
    use serde_json;

    use super::{Node, Nodes};

    #[test]
    fn nodes_serialization() {
        let expected_json = r#"{
            "nodes": [
                {
                    "id": 0,
                    "pk": "mDvVkGbiatTmwOAqr4AdExVpwvYSpSKLjU2NWjo8QP6S7oGwddmwbkZGnNMNcFC4F12rH9KEILnwQoezdpQnx/7/jO5MCQrml6QcRTkMiDHNaLQkZVkkqF5IA68QbCja",
                    "weight": 2
                },
                {
                    "id": 1,
                    "pk": "ry/I1KkEE6I7oeGJa2UbIWoCFBYfxc44I+kwvNSzVbAv4b5RqZ2NDRaPjSsM7QeiB27HgdoCZUqJdTBiT9e0COHWLxd1oxMU/FU9ua5VxOPmjg1WLVzXTzvQBbwHD0An",
                    "weight": 3
                },
                {
                    "id": 2,
                    "pk": "sFu/netaAwsw68JsC41uTw/Yq2IugZMh72n06WyRvTX2zsvkMbMAmSyWf3n7fRZxCDEjbrnEbatVnzpt7UUsUDb6zs1JTfEKCFor9y8tbgS7MCZx4B7ZkHKVIV+gsII0",
                    "weight": 0
                }
            ],
            "total_weight": 5,
            "accumulated_weights": [
                2,
                5
            ],
            "nodes_with_nonzero_weight": [
                0,
                1
            ]
        }"#.chars().filter(|c| !c.is_whitespace()).collect::<String>();

        let expected_nodes = Nodes {
            nodes: vec![
                Node {
                    id: 0,
                    pk: G2Element(vec![
                        152, 59, 213, 144, 102, 226, 106, 212, 230, 192, 224, 42, 175, 128, 29, 19,
                        21, 105, 194, 246, 18, 165, 34, 139, 141, 77, 141, 90, 58, 60, 64, 254,
                        146, 238, 129, 176, 117, 217, 176, 110, 70, 70, 156, 211, 13, 112, 80, 184,
                        23, 93, 171, 31, 210, 132, 32, 185, 240, 66, 135, 179, 118, 148, 39, 199,
                        254, 255, 140, 238, 76, 9, 10, 230, 151, 164, 28, 69, 57, 12, 136, 49, 205,
                        104, 180, 36, 101, 89, 36, 168, 94, 72, 3, 175, 16, 108, 40, 218,
                    ]),
                    weight: 2,
                },
                Node {
                    id: 1,
                    pk: G2Element(vec![
                        175, 47, 200, 212, 169, 4, 19, 162, 59, 161, 225, 137, 107, 101, 27, 33,
                        106, 2, 20, 22, 31, 197, 206, 56, 35, 233, 48, 188, 212, 179, 85, 176, 47,
                        225, 190, 81, 169, 157, 141, 13, 22, 143, 141, 43, 12, 237, 7, 162, 7, 110,
                        199, 129, 218, 2, 101, 74, 137, 117, 48, 98, 79, 215, 180, 8, 225, 214, 47,
                        23, 117, 163, 19, 20, 252, 85, 61, 185, 174, 85, 196, 227, 230, 142, 13,
                        86, 45, 92, 215, 79, 59, 208, 5, 188, 7, 15, 64, 39,
                    ]),
                    weight: 3,
                },
                Node {
                    id: 2,
                    pk: G2Element(vec![
                        176, 91, 191, 157, 235, 90, 3, 11, 48, 235, 194, 108, 11, 141, 110, 79, 15,
                        216, 171, 98, 46, 129, 147, 33, 239, 105, 244, 233, 108, 145, 189, 53, 246,
                        206, 203, 228, 49, 179, 0, 153, 44, 150, 127, 121, 251, 125, 22, 113, 8,
                        49, 35, 110, 185, 196, 109, 171, 85, 159, 58, 109, 237, 69, 44, 80, 54,
                        250, 206, 205, 73, 77, 241, 10, 8, 90, 43, 247, 47, 45, 110, 4, 187, 48,
                        38, 113, 224, 30, 217, 144, 114, 149, 33, 95, 160, 176, 130, 52,
                    ]),
                    weight: 0,
                },
            ],
            total_weight: 5,
            accumulated_weights: vec![2, 5],
            nodes_with_nonzero_weight: vec![0, 1],
        };

        let deserialized: Nodes = serde_json::from_str(&expected_json).unwrap();
        assert_eq!(expected_nodes, deserialized);

        let serialized = serde_json::to_string(&expected_nodes).unwrap();
        assert_eq!(expected_json.as_str(), serialized);
    }

    #[test]
    fn message_serialization() {
        let expected_json = r#"{
            "sender": 1,
            "vss_pk": [
                "laIyPQfJSe01Ue6EWlkq7gdk7PMPjlonvX50VxSNG4kH382EDYE/rdK7A/tVep/yGEKNRTF7B1rArNm9a2xvwq0OSvGcuOSl+EejANQ+X265VcZ300eHIIh23p0NsCb1",
                "hMMiuXoo2i64Iitmp3DEzORKxyhQACyYFQBOtufbmC0igBQVtHedVergJtEmeMgdAzm2sb3vwSKIkuNAvSUHtW8V8/utz4QJ0XA06vHlSaoJaa+/s3bxXMuV2nkY0gJG",
                "q/kVjg20b0HugG8z2Uc9OVlNNnguFMQXtV8zsJbny5pOu9JeNwoSZWkVqQsIQbkcBmk0KMrYa63lGpVUXMUCrtFJKK75CJGrAaTgc1qas6eHQO+byrD1dVQD0mWL+A7z"
            ],
            "encrypted_shares": [
                "jHL27S9wptgujjSn1m1iTKufHGoTwiDPOOGPFo4vBf0aic2ByALq/FGb7v/ZErsDDm7OWm65sVYet8vSyH/Keq7PmKyWf44SOQbdlW/j7E1FSWuZUQngnpYkVELSlMR3",
                [
                    [
                        232,
                        95,
                        105,
                        55,
                        48,
                        136,
                        19,
                        105,
                        153,
                        91,
                        7,
                        195,
                        149,
                        91,
                        196,
                        241,
                        185,
                        60,
                        101,
                        138,
                        221,
                        73,
                        54,
                        27,
                        17,
                        177,
                        11,
                        30,
                        98,
                        42,
                        161,
                        161,
                        71,
                        114,
                        150,
                        96,
                        253,
                        159,
                        192,
                        161,
                        55,
                        169,
                        249,
                        225,
                        109,
                        144,
                        102,
                        139,
                        6,
                        127,
                        168,
                        160,
                        9,
                        84,
                        68,
                        67,
                        101,
                        163,
                        20,
                        146,
                        115,
                        123,
                        233,
                        175,
                        31
                    ],
                    [
                        79,
                        8,
                        27,
                        249,
                        160,
                        212,
                        24,
                        69,
                        40,
                        42,
                        14,
                        124,
                        98,
                        159,
                        97,
                        195,
                        231,
                        216,
                        199,
                        15,
                        33,
                        73,
                        153,
                        49,
                        175,
                        127,
                        158,
                        112,
                        19,
                        54,
                        168,
                        28,
                        129,
                        96,
                        214,
                        198,
                        88,
                        139,
                        41,
                        240,
                        1,
                        5,
                        250,
                        238,
                        4,
                        209,
                        247,
                        92,
                        65,
                        133,
                        161,
                        19,
                        149,
                        23,
                        133,
                        77,
                        51,
                        86,
                        248,
                        122,
                        142,
                        133,
                        154,
                        2,
                        173,
                        79,
                        243,
                        148,
                        153,
                        53,
                        0,
                        205,
                        178,
                        189,
                        93,
                        137,
                        230,
                        249,
                        71,
                        156,
                        201,
                        173,
                        176,
                        76,
                        64,
                        42,
                        119,
                        101,
                        177,
                        174,
                        21,
                        124,
                        96,
                        69,
                        30,
                        57,
                        147
                    ],
                    [
                        90
                    ]
                ],
                [
                    "gkA/kvmi4YLOsSxqWy43BnEgWHnk8cNJS5GotdE2vzB6bngDm5kRN5e6VAY18lvyENA8fz57hR0X3kUmVowv8DFyKZjpuX8gIUlv6oJN7O+FyhG7wnKzFVaqdvIzZMRu",
                    "YdmOoYqWFX8JV/CNFxnktTTIebwrGrJbLngpnKs6ri4="
                ]
            ]
        }"#.chars().filter(|c| !c.is_whitespace()).collect::<String>();

        let expected_message = Message {
            sender: 1,
            vss_pk: vec![
                G2Element(vec![
                    149, 162, 50, 61, 7, 201, 73, 237, 53, 81, 238, 132, 90, 89, 42, 238, 7, 100,
                    236, 243, 15, 142, 90, 39, 189, 126, 116, 87, 20, 141, 27, 137, 7, 223, 205,
                    132, 13, 129, 63, 173, 210, 187, 3, 251, 85, 122, 159, 242, 24, 66, 141, 69,
                    49, 123, 7, 90, 192, 172, 217, 189, 107, 108, 111, 194, 173, 14, 74, 241, 156,
                    184, 228, 165, 248, 71, 163, 0, 212, 62, 95, 110, 185, 85, 198, 119, 211, 71,
                    135, 32, 136, 118, 222, 157, 13, 176, 38, 245,
                ]),
                G2Element(vec![
                    132, 195, 34, 185, 122, 40, 218, 46, 184, 34, 43, 102, 167, 112, 196, 204, 228,
                    74, 199, 40, 80, 0, 44, 152, 21, 0, 78, 182, 231, 219, 152, 45, 34, 128, 20,
                    21, 180, 119, 157, 85, 234, 224, 38, 209, 38, 120, 200, 29, 3, 57, 182, 177,
                    189, 239, 193, 34, 136, 146, 227, 64, 189, 37, 7, 181, 111, 21, 243, 251, 173,
                    207, 132, 9, 209, 112, 52, 234, 241, 229, 73, 170, 9, 105, 175, 191, 179, 118,
                    241, 92, 203, 149, 218, 121, 24, 210, 2, 70,
                ]),
                G2Element(vec![
                    171, 249, 21, 142, 13, 180, 111, 65, 238, 128, 111, 51, 217, 71, 61, 57, 89,
                    77, 54, 120, 46, 20, 196, 23, 181, 95, 51, 176, 150, 231, 203, 154, 78, 187,
                    210, 94, 55, 10, 18, 101, 105, 21, 169, 11, 8, 65, 185, 28, 6, 105, 52, 40,
                    202, 216, 107, 173, 229, 26, 149, 84, 92, 197, 2, 174, 209, 73, 40, 174, 249,
                    8, 145, 171, 1, 164, 224, 115, 90, 154, 179, 167, 135, 64, 239, 155, 202, 176,
                    245, 117, 84, 3, 210, 101, 139, 248, 14, 243,
                ]),
            ],
            encrypted_shares: MultiRecipientEncryption(
                G2Element(vec![
                    140, 114, 246, 237, 47, 112, 166, 216, 46, 142, 52, 167, 214, 109, 98, 76, 171,
                    159, 28, 106, 19, 194, 32, 207, 56, 225, 143, 22, 142, 47, 5, 253, 26, 137,
                    205, 129, 200, 2, 234, 252, 81, 155, 238, 255, 217, 18, 187, 3, 14, 110, 206,
                    90, 110, 185, 177, 86, 30, 183, 203, 210, 200, 127, 202, 122, 174, 207, 152,
                    172, 150, 127, 142, 18, 57, 6, 221, 149, 111, 227, 236, 77, 69, 73, 107, 153,
                    81, 9, 224, 158, 150, 36, 84, 66, 210, 148, 196, 119,
                ]),
                vec![
                    vec![
                        232, 95, 105, 55, 48, 136, 19, 105, 153, 91, 7, 195, 149, 91, 196, 241,
                        185, 60, 101, 138, 221, 73, 54, 27, 17, 177, 11, 30, 98, 42, 161, 161, 71,
                        114, 150, 96, 253, 159, 192, 161, 55, 169, 249, 225, 109, 144, 102, 139, 6,
                        127, 168, 160, 9, 84, 68, 67, 101, 163, 20, 146, 115, 123, 233, 175, 31,
                    ],
                    vec![
                        79, 8, 27, 249, 160, 212, 24, 69, 40, 42, 14, 124, 98, 159, 97, 195, 231,
                        216, 199, 15, 33, 73, 153, 49, 175, 127, 158, 112, 19, 54, 168, 28, 129,
                        96, 214, 198, 88, 139, 41, 240, 1, 5, 250, 238, 4, 209, 247, 92, 65, 133,
                        161, 19, 149, 23, 133, 77, 51, 86, 248, 122, 142, 133, 154, 2, 173, 79,
                        243, 148, 153, 53, 0, 205, 178, 189, 93, 137, 230, 249, 71, 156, 201, 173,
                        176, 76, 64, 42, 119, 101, 177, 174, 21, 124, 96, 69, 30, 57, 147,
                    ],
                    vec![90],
                ],
                DLNizk(
                    G2Element(vec![
                        130, 64, 63, 146, 249, 162, 225, 130, 206, 177, 44, 106, 91, 46, 55, 6,
                        113, 32, 88, 121, 228, 241, 195, 73, 75, 145, 168, 181, 209, 54, 191, 48,
                        122, 110, 120, 3, 155, 153, 17, 55, 151, 186, 84, 6, 53, 242, 91, 242, 16,
                        208, 60, 127, 62, 123, 133, 29, 23, 222, 69, 38, 86, 140, 47, 240, 49, 114,
                        41, 152, 233, 185, 127, 32, 33, 73, 111, 234, 130, 77, 236, 239, 133, 202,
                        17, 187, 194, 114, 179, 21, 86, 170, 118, 242, 51, 100, 196, 110,
                    ]),
                    Scalar(vec![
                        97, 217, 142, 161, 138, 150, 21, 127, 9, 87, 240, 141, 23, 25, 228, 181,
                        52, 200, 121, 188, 43, 26, 178, 91, 46, 120, 41, 156, 171, 58, 174, 46,
                    ]),
                ),
            ),
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
            "complaints": [
                {
                    "accused_sender": 1,
                    "proof": {
                        "ephemeral_key": "jYH9sg+DlnqRTQx1yMmH2Yytmd4wkB7KO5X5DKrGuk7QN4+hvr48AylZq84SWuZzD9S72zHRCE0XvTbw3FINHIEXuhE74W7l0MUKPtrEXfJUfSefbmLlJAmqTbw39SMe",
                        "proof": [
                            "jXW4CgMXZXte6Pti8YVLz4VKsioZuUrx8Yq1twzDQ8g5djEHYKmCcc5jnxP1Q3QMFDgpyrXLAb93EVcAaoCxck5pfKtMI2b7aEQ5SyIjJ2dhz8760CRyqNWrDKtJQ7qB",
                            "jCMMOVBlRzoOqXEhuWz63V3RYchZBsgSuymAkxyQF0dukN1mNU/8KSO3m0/cvlMZCWZshlG9svbZFOG9KCsrcFUx2NyswjTJ+2mHwLdf3OLM5gH+BJ7ExMClbVIzQB4M",
                            "Q2/haZnSPsxTMc2xk4mP3hfBhYy1YXVoFbpqE71iaME="
                        ]
                    }
                }
            ]
        }"#.chars().filter(|c| !c.is_whitespace()).collect::<String>();

        let expected_confirmation = Confirmation {
            sender: 0,
            complaints: vec![Complaint {
                accused_sender: 1,
                proof: RecoveryPackage {
                    ephemeral_key: G2Element(vec![
                        141, 129, 253, 178, 15, 131, 150, 122, 145, 77, 12, 117, 200, 201, 135,
                        217, 140, 173, 153, 222, 48, 144, 30, 202, 59, 149, 249, 12, 170, 198, 186,
                        78, 208, 55, 143, 161, 190, 190, 60, 3, 41, 89, 171, 206, 18, 90, 230, 115,
                        15, 212, 187, 219, 49, 209, 8, 77, 23, 189, 54, 240, 220, 82, 13, 28, 129,
                        23, 186, 17, 59, 225, 110, 229, 208, 197, 10, 62, 218, 196, 93, 242, 84,
                        125, 39, 159, 110, 98, 229, 36, 9, 170, 77, 188, 55, 245, 35, 30,
                    ]),
                    proof: DdhTupleNizk(
                        G2Element(vec![
                            141, 117, 184, 10, 3, 23, 101, 123, 94, 232, 251, 98, 241, 133, 75,
                            207, 133, 74, 178, 42, 25, 185, 74, 241, 241, 138, 181, 183, 12, 195,
                            67, 200, 57, 118, 49, 7, 96, 169, 130, 113, 206, 99, 159, 19, 245, 67,
                            116, 12, 20, 56, 41, 202, 181, 203, 1, 191, 119, 17, 87, 0, 106, 128,
                            177, 114, 78, 105, 124, 171, 76, 35, 102, 251, 104, 68, 57, 75, 34, 35,
                            39, 103, 97, 207, 206, 250, 208, 36, 114, 168, 213, 171, 12, 171, 73,
                            67, 186, 129,
                        ]),
                        G2Element(vec![
                            140, 35, 12, 57, 80, 101, 71, 58, 14, 169, 113, 33, 185, 108, 250, 221,
                            93, 209, 97, 200, 89, 6, 200, 18, 187, 41, 128, 147, 28, 144, 23, 71,
                            110, 144, 221, 102, 53, 79, 252, 41, 35, 183, 155, 79, 220, 190, 83,
                            25, 9, 102, 108, 134, 81, 189, 178, 246, 217, 20, 225, 189, 40, 43, 43,
                            112, 85, 49, 216, 220, 172, 194, 52, 201, 251, 105, 135, 192, 183, 95,
                            220, 226, 204, 230, 1, 254, 4, 158, 196, 196, 192, 165, 109, 82, 51,
                            64, 30, 12,
                        ]),
                        Scalar(vec![
                            67, 111, 225, 105, 153, 210, 62, 204, 83, 49, 205, 177, 147, 137, 143,
                            222, 23, 193, 133, 140, 181, 97, 117, 104, 21, 186, 106, 19, 189, 98,
                            104, 193,
                        ]),
                    ),
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
            "threshold":2,
            "nodes": {
                "nodes":[
                    {
                        "id":0,
                        "pk":"mDvVkGbiatTmwOAqr4AdExVpwvYSpSKLjU2NWjo8QP6S7oGwddmwbkZGnNMNcFC4F12rH9KEILnwQoezdpQnx/7/jO5MCQrml6QcRTkMiDHNaLQkZVkkqF5IA68QbCja",
                        "weight":2
                    },
                    {
                        "id":1,
                        "pk":"ry/I1KkEE6I7oeGJa2UbIWoCFBYfxc44I+kwvNSzVbAv4b5RqZ2NDRaPjSsM7QeiB27HgdoCZUqJdTBiT9e0COHWLxd1oxMU/FU9ua5VxOPmjg1WLVzXTzvQBbwHD0An",
                        "weight":3
                    },
                    {
                        "id":2,
                        "pk":"sFu/netaAwsw68JsC41uTw/Yq2IugZMh72n06WyRvTX2zsvkMbMAmSyWf3n7fRZxCDEjbrnEbatVnzpt7UUsUDb6zs1JTfEKCFor9y8tbgS7MCZx4B7ZkHKVIV+gsII0",
                        "weight":0
                    }
                ],
                "total_weight": 5,
                "accumulated_weights": [
                    2,
                    5
                ],
                "nodes_with_nonzero_weight": [
                    0,
                    1
                ]
            },
            "messages":[],
            "confirmations":[]
        }"#.chars().filter(|c| !c.is_whitespace()).collect::<String>();
        let expected_session = Session {
            threshold: 2,
            nodes: Nodes {
                nodes: vec![
                    Node {
                        id: 0,
                        pk: G2Element(vec![
                            152, 59, 213, 144, 102, 226, 106, 212, 230, 192, 224, 42, 175, 128, 29,
                            19, 21, 105, 194, 246, 18, 165, 34, 139, 141, 77, 141, 90, 58, 60, 64,
                            254, 146, 238, 129, 176, 117, 217, 176, 110, 70, 70, 156, 211, 13, 112,
                            80, 184, 23, 93, 171, 31, 210, 132, 32, 185, 240, 66, 135, 179, 118,
                            148, 39, 199, 254, 255, 140, 238, 76, 9, 10, 230, 151, 164, 28, 69, 57,
                            12, 136, 49, 205, 104, 180, 36, 101, 89, 36, 168, 94, 72, 3, 175, 16,
                            108, 40, 218,
                        ]),
                        weight: 2,
                    },
                    Node {
                        id: 1,
                        pk: G2Element(vec![
                            175, 47, 200, 212, 169, 4, 19, 162, 59, 161, 225, 137, 107, 101, 27,
                            33, 106, 2, 20, 22, 31, 197, 206, 56, 35, 233, 48, 188, 212, 179, 85,
                            176, 47, 225, 190, 81, 169, 157, 141, 13, 22, 143, 141, 43, 12, 237, 7,
                            162, 7, 110, 199, 129, 218, 2, 101, 74, 137, 117, 48, 98, 79, 215, 180,
                            8, 225, 214, 47, 23, 117, 163, 19, 20, 252, 85, 61, 185, 174, 85, 196,
                            227, 230, 142, 13, 86, 45, 92, 215, 79, 59, 208, 5, 188, 7, 15, 64, 39,
                        ]),
                        weight: 3,
                    },
                    Node {
                        id: 2,
                        pk: G2Element(vec![
                            176, 91, 191, 157, 235, 90, 3, 11, 48, 235, 194, 108, 11, 141, 110, 79,
                            15, 216, 171, 98, 46, 129, 147, 33, 239, 105, 244, 233, 108, 145, 189,
                            53, 246, 206, 203, 228, 49, 179, 0, 153, 44, 150, 127, 121, 251, 125,
                            22, 113, 8, 49, 35, 110, 185, 196, 109, 171, 85, 159, 58, 109, 237, 69,
                            44, 80, 54, 250, 206, 205, 73, 77, 241, 10, 8, 90, 43, 247, 47, 45,
                            110, 4, 187, 48, 38, 113, 224, 30, 217, 144, 114, 149, 33, 95, 160,
                            176, 130, 52,
                        ]),
                        weight: 0,
                    },
                ],
                total_weight: 5,
                accumulated_weights: vec![2, 5],
                nodes_with_nonzero_weight: vec![0, 1],
            },
            messages: vec![],
            confirmations: vec![],
        };

        let deserialize: Session = serde_json::from_str(&expected_json).unwrap();
        assert_eq!(expected_session, deserialize);

        let serialize = serde_json::to_string(&expected_session).unwrap();
        assert_eq!(expected_json.as_str(), serialize);
    }
}
