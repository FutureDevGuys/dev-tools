//! Dynamic JSON must not erase duplicate member ambiguity before pointer lookup.
pub(super) fn parse(bytes: &[u8]) -> serde_json::Result<serde_json::Value> {
    serde_json::from_slice::<UniqueValue>(bytes).map(|value| value.0)
}

struct UniqueValue(serde_json::Value);

impl<'de> serde::Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value without duplicate object members")
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::Null))
            }

            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::Bool(value)))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::Number(value.into())))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::Number(value.into())))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                let number = serde_json::Number::from_f64(value)
                    .ok_or_else(|| E::custom("JSON number is not finite"))?;
                Ok(UniqueValue(serde_json::Value::Number(number)))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::String(value.to_owned())))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::String(value)))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(serde_json::Value::Array(values)))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueValue>()? {
                    if values.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON object member"));
                    }
                }
                Ok(UniqueValue(serde_json::Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_members_are_rejected_at_every_depth_and_after_json_unescaping() {
        for bytes in [
            br#"{"releases":[],"releases":[1]}"#.as_slice(),
            br#"{"nested":{"key":1,"key":2}}"#,
            br#"{"key":1,"\u006bey":2}"#,
        ] {
            assert!(
                parse(bytes).is_err(),
                "duplicate members must not be collapsed"
            );
        }
    }

    #[test]
    fn ordinary_values_and_pointer_escape_rules_remain_intact() {
        let value = serde_json::json!({"outer/key": {"tilde~key": [null, true, -1, u64::MAX, 1.5, "text"]}});
        let parsed = parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(parsed, value);
        assert_eq!(parsed.pointer("/outer~1key/tilde~0key/5").unwrap(), "text");
        assert!(parsed.pointer("/outer~1key/tilde~0key/05").is_none());
        let nested = format!("{}0{}", "[".repeat(256), "]".repeat(256));
        assert!(
            parse(nested.as_bytes()).is_err(),
            "the JSON nesting guard remains enabled"
        );
    }
}
