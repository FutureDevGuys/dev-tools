use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const ENV_NAME: &str = "DEV_CACHE_PROVENANCE";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Provenance {
    schema_version: u32,
    #[serde(default)]
    variables: HashMap<String, ManagedVariable>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ManagedVariable {
    resource: String,
    value: String,
}

pub fn inherited_is_managed(inherited: &HashMap<String, String>, name: &str) -> bool {
    let Some(current) = inherited.get(name) else {
        return false;
    };
    parse(inherited)
        .and_then(|record| record.variables.get(name).cloned())
        .is_some_and(|record| record.value == *current)
}

pub fn attach(
    inherited: &HashMap<String, String>,
    routed: &mut HashMap<String, String>,
    resource: &str,
) {
    if routed.is_empty() {
        return;
    }
    let mut provenance = parse(inherited).unwrap_or_default();
    provenance.schema_version = 1;
    provenance.variables.retain(|name, record| {
        inherited
            .get(name)
            .is_some_and(|value| value == &record.value)
    });
    for (name, value) in routed.iter() {
        provenance.variables.insert(
            name.clone(),
            ManagedVariable {
                resource: resource.to_owned(),
                value: value.clone(),
            },
        );
    }
    if let Ok(serialized) = serde_json::to_string(&provenance) {
        routed.insert(ENV_NAME.to_owned(), serialized);
    }
}

fn parse(inherited: &HashMap<String, String>) -> Option<Provenance> {
    let raw = inherited.get(ENV_NAME)?;
    let parsed: Provenance = serde_json::from_str(raw).ok()?;
    (parsed.schema_version == 1).then_some(parsed)
}

pub fn process_report() -> Option<serde_json::Value> {
    let inherited: HashMap<String, String> = std::env::vars().collect();
    parse(&inherited).and_then(|value| serde_json::to_value(value).ok())
}
