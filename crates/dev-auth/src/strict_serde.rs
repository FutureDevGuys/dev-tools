use serde::Deserialize;

// Serde's internally tagged unit visitor ignores remaining map fields even
// when the enum denies unknown fields. Preserve public unit variants while
// requiring their authority-bearing representation to contain no options.
pub(crate) fn empty_variant<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<(), D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    Empty::deserialize(deserializer).map(|_| ())
}
