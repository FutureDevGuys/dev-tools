use anyhow::Result;
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct Sections {
    pub only: Option<BTreeSet<String>>,
    pub exclude: BTreeSet<String>,
}

impl Sections {
    pub fn from_cli_selectors(only: &Option<String>, exclude: &Option<String>) -> Result<Self> {
        Ok(Self {
            only: only.as_ref().map(|value| parse_selectors(value)),
            exclude: exclude
                .as_ref()
                .map(|value| parse_selectors(value))
                .unwrap_or_default(),
        })
    }
}

fn parse_selectors(raw: &str) -> BTreeSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::Sections;
    use std::collections::BTreeSet;

    #[test]
    fn only_selectors_are_catalog_ids_or_categories() {
        let sections = Sections::from_cli_selectors(&Some("rust,go,custom".to_string()), &None)
            .expect("parse only selectors");
        assert_eq!(
            sections.only,
            Some(BTreeSet::from([
                "custom".to_string(),
                "go".to_string(),
                "rust".to_string(),
            ]))
        );
    }

    #[test]
    fn exclude_selectors_are_normalized() {
        let sections = Sections::from_cli_selectors(
            &None,
            &Some(" System, builtin/demo ,system ".to_string()),
        )
        .unwrap();
        assert_eq!(
            sections.exclude,
            BTreeSet::from(["builtin/demo".to_string(), "system".to_string()])
        );
    }
}
