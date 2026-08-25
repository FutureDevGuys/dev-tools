pub(crate) fn print_build_info() {
    let built_unix = option_env!("DEV_TOOLS_BUILD_UNIX")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let payload = serde_json::json!({
        "profile": option_env!("DEV_TOOLS_BUILD_PROFILE").unwrap_or("unknown"),
        "built_unix": built_unix,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
    );
}
