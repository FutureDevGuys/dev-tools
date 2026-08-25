use anyhow::Result;
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
#[allow(dead_code)] // Reason: flag surface stays ahead of currently runnable sections.
pub struct Sections {
    pub npm: bool,
    pub pipx: bool,
    pub system: bool,
    // currently stubbed/flag-compatible:
    pub custom: bool,
    pub go: bool,
    pub uv: bool,
    pub uvx: bool,
    pub espanso: bool,
    pub rustup: bool,
    pub cargo: bool,
    pub cursor: bool,
    pub bootstrap: bool,
    pub only: Option<BTreeSet<String>>,
    pub exclude: BTreeSet<String>,
}

impl Sections {
    pub fn from_cli_selectors(only: &Option<String>, exclude: &Option<String>) -> Result<Self> {
        let mut s = Sections {
            npm: true,
            pipx: true,
            system: true,
            custom: true,
            go: true,
            uv: true,
            uvx: true,
            espanso: true,
            rustup: true,
            cargo: true,
            cursor: true,
            bootstrap: false,
            only: None,
            exclude: parse_selectors(exclude),
        };

        if let Some(only) = only {
            let mut selected = BTreeSet::new();
            s = Sections {
                npm: false,
                pipx: false,
                system: false,
                custom: false,
                go: false,
                uv: false,
                uvx: false,
                espanso: false,
                rustup: false,
                cargo: false,
                cursor: false,
                bootstrap: false,
                only: None,
                exclude: s.exclude,
            };

            for raw in only.split(',') {
                let name = raw.trim().to_lowercase();
                match name.as_str() {
                    "bootstrap" => {
                        s.bootstrap = true;
                        selected.insert("bootstrap-windows-foundations".to_string());
                    }
                    "" => {}
                    other => {
                        selected.insert(other.to_string());
                    }
                }
            }
            s.only = Some(selected);
        }

        Ok(s)
    }
}

fn parse_selectors(raw: &Option<String>) -> BTreeSet<String> {
    raw.as_deref()
        .into_iter()
        .flat_map(|value| value.split(','))
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
    fn only_selectors_are_catalog_driven_after_bootstrap_alias() {
        let sections =
            Sections::from_cli_selectors(&Some("rust,go,custom,bootstrap".to_string()), &None)
                .expect("parse only selectors");

        assert_eq!(
            sections.only,
            Some(BTreeSet::from([
                "custom".to_string(),
                "go".to_string(),
                "bootstrap-windows-foundations".to_string(),
                "rust".to_string()
            ]))
        );
        assert!(sections.bootstrap);
        assert!(!sections.custom);
        assert!(!sections.go);
        assert!(!sections.rustup);
        assert!(!sections.cargo);
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
