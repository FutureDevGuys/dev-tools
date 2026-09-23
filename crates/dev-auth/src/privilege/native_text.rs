//! Lossless human/native string encoding shared by components of Dev Auth.

use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use std::ffi::OsString;

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Text {
    Unicode(String),
    Native(Native),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Native {
    #[serde(rename = "unix_bytes")]
    Unix(Vec<u8>),
    #[serde(rename = "windows_utf16")]
    Windows(Vec<u16>),
}

impl From<&OsString> for Text {
    fn from(value: &OsString) -> Self {
        if let Some(value) = value.to_str() {
            return Self::Unicode(value.to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Self::Native(Native::Unix(value.as_bytes().to_vec()))
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            Self::Native(Native::Windows(value.encode_wide().collect()))
        }
    }
}

impl Text {
    fn into_native<E: serde::de::Error>(self) -> Result<OsString, E> {
        match self {
            Self::Unicode(value) => Ok(value.into()),
            #[cfg(unix)]
            Self::Native(Native::Unix(bytes)) => {
                use std::os::unix::ffi::OsStringExt;
                Ok(OsString::from_vec(bytes))
            }
            #[cfg(windows)]
            Self::Native(Native::Windows(units)) => {
                use std::os::windows::ffi::OsStringExt;
                Ok(OsString::from_wide(&units))
            }
            _ => Err(E::custom("foreign native string representation")),
        }
    }
}

pub fn serialize<S: Serializer>(value: &OsString, serializer: S) -> Result<S::Ok, S::Error> {
    Text::from(value).serialize(serializer)
}
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<OsString, D::Error> {
    Text::deserialize(deserializer)?.into_native()
}
pub mod sequence {
    use super::*;
    pub fn serialize<S: Serializer>(values: &[OsString], serializer: S) -> Result<S::Ok, S::Error> {
        values
            .iter()
            .map(Text::from)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<OsString>, D::Error> {
        Vec::<Text>::deserialize(deserializer)?
            .into_iter()
            .map(Text::into_native)
            .collect()
    }
}
pub mod environment {
    use super::*;
    pub fn serialize<S: Serializer>(
        values: &[(OsString, OsString)],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        values
            .iter()
            .map(|(name, value)| (Text::from(name), Text::from(value)))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<(OsString, OsString)>, D::Error> {
        Vec::<(Text, Text)>::deserialize(deserializer)?
            .into_iter()
            .map(|(name, value)| Ok((name.into_native()?, value.into_native()?)))
            .collect()
    }
}
