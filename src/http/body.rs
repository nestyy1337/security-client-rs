use std::{collections::HashSet, fmt};

use bytes::Bytes;
use reqwest::multipart::{Form, Part};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;

use crate::{Error, Result};

/// A request body. Endpoint builders create these; use them directly with
/// [`Transport::send`](super::Transport::send) or [`Request::body`](crate::Request::body).
///
/// Cloning shares the encoded bytes.
#[derive(Clone)]
pub struct Body(pub(crate) Content);

#[derive(Clone)]
pub(crate) enum Content {
    Json(Bytes),
    File {
        field: String,
        file_name: String,
        content_type: String,
        bytes: Bytes,
    },
}

impl Body {
    /// Fails with [`Error::InvalidRequest`] when the JSON would repeat an object
    /// key, as a flattened extension map repeating a modeled field does.
    pub fn json<T: Serialize + ?Sized>(value: &T) -> Result<Self> {
        Ok(Self(Content::Json(encode_json(value)?.into())))
    }

    /// A `multipart/form-data` body with a single file part, as used by Kibana import APIs.
    pub fn file(
        field: impl Into<String>,
        file_name: impl Into<String>,
        content_type: &str,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        Part::bytes(Vec::new())
            .mime_str(content_type)
            .map_err(|_| Error::InvalidRequest(format!("invalid content type {content_type:?}")))?;
        Ok(Self(Content::File {
            field: field.into(),
            file_name: file_name.into(),
            content_type: content_type.to_owned(),
            bytes: Bytes::from(bytes.into()),
        }))
    }
}

impl Content {
    pub(crate) fn form(
        field: String,
        file_name: String,
        content_type: &str,
        bytes: Bytes,
    ) -> Result<Form> {
        let length = bytes.len() as u64;
        let part = Part::stream_with_length(bytes, length)
            .file_name(file_name)
            .mime_str(content_type)
            .map_err(|_| Error::InvalidRequest(format!("invalid content type {content_type:?}")))?;
        Ok(Form::new().part(field, part))
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Content::Json(bytes) => write!(f, "Body::Json({} bytes)", bytes.len()),
            Content::File {
                file_name, bytes, ..
            } => {
                write!(f, "Body::File({file_name:?}, {} bytes)", bytes.len())
            }
        }
    }
}

/// Serializes `value` as JSON, rejecting objects that repeat a key.
///
/// A struct whose flattened extension map repeats a modeled field, such as
/// `id`, serializes that key twice; `serde_json::to_value` would silently keep
/// the extension's value, so the transmitted identity would differ from the
/// typed one.
pub(crate) fn to_json<T: Serialize + ?Sized>(value: &T) -> Result<Value> {
    encode_json(value)?;
    serde_json::to_value(value).map_err(Error::serialize)
}

fn encode_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(value).map_err(Error::serialize)?;
    let mut decoder = serde_json::Deserializer::from_slice(&encoded);
    Unique::deserialize(&mut decoder)
        .and_then(|_| decoder.end())
        .map_err(|error| Error::InvalidRequest(format!("request body {error}")))?;
    Ok(encoded)
}

/// Validates object keys without retaining or converting values.
struct Unique;

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor).map(|()| Unique)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        while seq.next_element::<Unique>()?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if keys.contains(&key) {
                return Err(de::Error::custom(format_args!(
                    "repeats the field {key:?}; an extension map may not set a modeled field"
                )));
            }
            keys.insert(key);
            map.next_value::<Unique>()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, json};

    use super::*;

    #[test]
    fn json_keeps_encoded_numbers_exactly() {
        #[derive(Serialize)]
        struct Numbers {
            positive: u128,
            negative: i128,
            fraction: f64,
        }
        let numbers = Numbers {
            positive: u64::MAX as u128 + 2,
            negative: i64::MIN as i128 - 2,
            fraction: 2.291712365432881e-9,
        };
        let Content::Json(bytes) = Body::json(&numbers).unwrap().0 else {
            panic!("expected JSON");
        };
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            serde_json::to_string(&numbers).unwrap()
        );
    }

    #[test]
    fn repeated_keys_are_rejected_at_any_depth() {
        #[derive(Serialize)]
        struct Flattened {
            id: &'static str,
            #[serde(flatten)]
            extra: Map<String, Value>,
        }
        let clean = Flattened {
            id: "a",
            extra: Map::from_iter([("color".into(), json!("red"))]),
        };
        assert_eq!(to_json(&clean).unwrap(), json!({"id": "a", "color": "red"}));

        let colliding = Flattened {
            id: "a",
            extra: Map::from_iter([("id".into(), json!("b"))]),
        };
        let error = to_json(&colliding).unwrap_err();
        assert!(
            matches!(&error, Error::InvalidRequest(m) if m.contains("\"id\"")),
            "{error:?}"
        );
        assert!(to_json(&json!({"outer": [colliding.extra.clone()]})).is_ok());
        assert!(Body::json(&colliding).is_err());
        assert!(to_json(&vec![colliding]).is_err());
        assert!(Body::json(&clean).is_ok());
    }
}
