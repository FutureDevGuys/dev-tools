use super::*;
use crate::completions::generator::{generate_tool_completion, CompletionGenerationRequest};
use crate::test_support::{env_guard, write_executable};
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;

struct EnvVarGuard {
    key: &'static str,
    old: Option<OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: impl Into<OsString>) -> Self {
        let old = env::var_os(key);
        env::set_var(key, value.into());
        Self { key, old }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(old) = self.old.take() {
            env::set_var(self.key, old);
        } else {
            env::remove_var(self.key);
        }
    }
}

fn with_isolated_environment<T>(body: impl FnOnce(&TempDir, &Path) -> T) -> T {
    let _environment = env_guard();
    let temp = TempDir::new().unwrap();
    let bin = temp.path().join("isolated-path");
    fs::create_dir_all(&bin).unwrap();
    let _path = EnvVarGuard::set("PATH", bin.as_os_str().to_os_string());
    body(&temp, &bin)
}

fn limits() -> NativeProbeLimits {
    NativeProbeLimits {
        per_probe_timeout: Duration::from_secs(2),
        total_timeout: Duration::from_secs(15),
        attempt_limit: 192,
        stdout_limit: 1024 * 1024,
        stderr_limit: 256 * 1024,
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn sh_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn argv_key(args: &[String]) -> String {
    args.join("|")
}

fn script_with_cases(cases: &[(Vec<String>, String)]) -> String {
    let mut script = String::from(
        "#!/bin/sh\nkey=''\nfor arg in \"$@\"; do\n  if [ -z \"$key\" ]; then\n    key=$arg\n  else\n    key=\"$key|$arg\"\n  fi\ndone\ncase \"$key\" in\n",
    );
    for (args, output) in cases {
        script.push_str("  ");
        script.push_str(&sh_single_quote(&argv_key(args)));
        script.push_str(")\n    printf '%s' ");
        script.push_str(&sh_single_quote(output));
        script.push_str("\n    exit 0\n    ;;\n");
    }
    script.push_str("esac\nexit 1\n");
    script
}

fn write_case_executable(path: &Path, cases: &[(Vec<String>, String)]) {
    write_executable(path, &script_with_cases(cases)).unwrap();
}

fn valid_payload(shell: CompletionShell, command: &str) -> String {
    match shell {
        CompletionShell::Bash => format!(
            "_{command}_completion() {{ COMPREPLY=(); }}\ncomplete -F _{command}_completion {command}\n"
        ),
        CompletionShell::Zsh => format!(
            "#compdef {command}\n_{command}() {{\n  _arguments '--alpha[alpha]'\n}}\n"
        ),
        CompletionShell::Fish => {
            format!("complete -c {command} -l alpha -d 'alpha'\n")
        }
        CompletionShell::Elvish => format!(
            "set edit:completion:arg-completer[{command}] = {{|@words| put alpha }}\n"
        ),
        CompletionShell::PowerShell => format!(
            "Register-ArgumentCompleter -Native -CommandName {command} -ScriptBlock {{ param($wordToComplete, $commandAst, $cursorPosition) 'alpha' }}\n"
        ),
    }
}

fn dynamic_bash_payload(command: &str) -> String {
    format!(
        "_{command}_completion() {{ {command} \"$@\"; }}\ncomplete -F _{command}_completion {command}\n"
    )
}

fn dynamic_zsh_payload(command: &str) -> String {
    format!("#compdef {command}\n_{command}() {{ {command} \"$@\"; }}\n")
}

fn evasive_dynamic_bash_payload(command: &str) -> String {
    format!(
        "_{command}_completion() {{ opaque-helper --candidate \"$1\"; }}\ncomplete -F _{command}_completion {command}\n"
    )
}

#[allow(clippy::too_many_arguments)]
fn run_plan(
    shell: CompletionShell,
    command_path: &Path,
    launch_args: &[String],
    provider_bin_dir: &Path,
    bundled_completions: &[RegistryBundledCompletion],
    catalog_recipes: &[RegistryCompletionRecipe],
    previous_recipe: Option<&NativeRecipeMemo>,
    origin: NativeCandidateOrigin,
    trust_dynamic: bool,
    probe_limits: NativeProbeLimits,
) -> (std::result::Result<NativePlannerOutcome, String>, usize) {
    let command = CompletionCommandSpec {
        program: command_path.to_path_buf(),
        args: launch_args.to_vec(),
    };
    let request = NativeCompletionRequest {
        shell,
        command_name: "demo",
        command: &command,
        provider_bin_dir,
        bundled_completions,
        catalog_recipes,
        previous_recipe,
        origin,
        trust_dynamic,
    };
    let mut session = NativeProbeSession::with_limits(probe_limits);
    let outcome = plan_native_completion(request, &mut session);
    (outcome, session.attempts_used())
}

fn run_managed_plan(
    shell: CompletionShell,
    command_path: &Path,
    provider_bin_dir: &Path,
    bundled_completions: &[RegistryBundledCompletion],
    catalog_recipes: &[RegistryCompletionRecipe],
    previous_recipe: Option<&NativeRecipeMemo>,
) -> (std::result::Result<NativePlannerOutcome, String>, usize) {
    run_plan(
        shell,
        command_path,
        &[],
        provider_bin_dir,
        bundled_completions,
        catalog_recipes,
        previous_recipe,
        NativeCandidateOrigin::Managed,
        false,
        limits(),
    )
}

fn expect_completion(
    outcome: std::result::Result<NativePlannerOutcome, String>,
) -> NativeCompletion {
    match outcome {
        Ok(NativePlannerOutcome::Completion(completion)) => completion,
        Ok(NativePlannerOutcome::NotFound { diagnostics, .. }) => {
            panic!("expected completion, got rejections: {diagnostics:?}")
        }
        Err(error) => panic!("expected completion, got error: {error}"),
    }
}

fn expect_not_found(
    outcome: std::result::Result<NativePlannerOutcome, String>,
) -> NativePlannerDiagnostics {
    match outcome {
        Ok(NativePlannerOutcome::NotFound { diagnostics, .. }) => diagnostics,
        Ok(NativePlannerOutcome::Completion(completion)) => {
            panic!("expected rejection, got completion: {completion:?}")
        }
        Err(error) => panic!("expected soft rejection, got error: {error}"),
    }
}

fn process_invocation(completion: &NativeCompletion) -> (&[String], &BTreeMap<String, String>) {
    match &completion.recipe.invocation {
        NativeRecipeInvocation::Process { args, env } => (args, env),
        NativeRecipeInvocation::StaticFile { path } => {
            panic!(
                "expected process recipe, got static file {}",
                path.display()
            )
        }
    }
}

fn assert_bash_protocol(expected_args: &[&str]) {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        let expected = strings(expected_args);
        write_case_executable(
            &command,
            &[(
                expected.clone(),
                valid_payload(CompletionShell::Bash, "demo"),
            )],
        );
        let (outcome, _) = run_managed_plan(CompletionShell::Bash, &command, bin, &[], &[], None);
        let completion = expect_completion(outcome);
        assert_eq!(process_invocation(&completion).0, expected.as_slice());
        assert_eq!(completion.recipe.source, NativeRecipeSource::StdoutProtocol);
    });
}

#[test]
fn native_protocol_positional_shell_names_cover_all_five_shells() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        let shells = [
            (CompletionShell::Bash, "bash"),
            (CompletionShell::Zsh, "zsh"),
            (CompletionShell::Fish, "fish"),
            (CompletionShell::Elvish, "elvish"),
            (CompletionShell::PowerShell, "powershell"),
        ];
        let cases = shells
            .iter()
            .map(|(shell, shell_name)| {
                (
                    strings(&["completion", shell_name]),
                    valid_payload(*shell, "demo"),
                )
            })
            .collect::<Vec<_>>();
        write_case_executable(&command, &cases);

        for (shell, shell_name) in shells {
            let (outcome, attempts) = run_managed_plan(shell, &command, bin, &[], &[], None);
            let completion = expect_completion(outcome);
            assert_eq!(attempts, 1);
            assert_eq!(
                process_invocation(&completion).0,
                strings(&["completion", shell_name]).as_slice()
            );
            assert_eq!(completion.bytes, valid_payload(shell, "demo").into_bytes());
            let expected_classification = match shell {
                CompletionShell::Fish => CompletionArtifactClassification::Static,
                CompletionShell::Bash
                | CompletionShell::Zsh
                | CompletionShell::Elvish
                | CompletionShell::PowerShell => CompletionArtifactClassification::Dynamic,
            };
            assert_eq!(completion.classification, expected_classification);
        }
    });
}

#[test]
fn native_protocol_completion_family_is_supported() {
    assert_bash_protocol(&["completion", "bash"]);
}

#[test]
fn native_protocol_completions_family_is_supported() {
    assert_bash_protocol(&["completions", "bash"]);
}

#[test]
fn native_protocol_generate_completion_family_is_supported() {
    assert_bash_protocol(&["generate-completion", "bash"]);
}

#[test]
fn native_protocol_generate_completions_family_is_supported() {
    assert_bash_protocol(&["generate-completions", "bash"]);
}

#[test]
fn native_protocol_gen_completion_family_is_supported() {
    assert_bash_protocol(&["gen-completion", "bash"]);
}

#[test]
fn native_protocol_top_level_completion_family_is_supported() {
    assert_bash_protocol(&["--completion=bash"]);
}

#[test]
fn native_protocol_top_level_completions_family_is_supported() {
    assert_bash_protocol(&["--completions=bash"]);
}

#[test]
fn native_protocol_top_level_show_completion_family_is_supported() {
    assert_bash_protocol(&["--show-completion=bash"]);
}

#[test]
fn native_protocol_top_level_flags_accept_positional_shell_arguments() {
    for head in ["--completion", "--completions", "--show-completion"] {
        assert_bash_protocol(&[head, "bash"]);
    }
}

#[test]
fn native_protocol_shell_flag_separate_and_joined_forms_require_help_evidence() {
    with_isolated_environment(|temp, bin| {
        let root_help = "Usage: demo\nCommands:\n  completion  Generate completion\n";
        let nested_help = "Usage: demo completion [OPTIONS]\nOptions:\n  --shell <shell>\n";
        let payload = valid_payload(CompletionShell::Bash, "demo");

        let separated = temp.path().join("demo-separated");
        write_case_executable(
            &separated,
            &[
                (strings(&["--help"]), root_help.to_string()),
                (strings(&["completion", "--help"]), nested_help.to_string()),
                (strings(&["completion", "--shell", "bash"]), payload.clone()),
            ],
        );
        let (outcome, _) = run_managed_plan(CompletionShell::Bash, &separated, bin, &[], &[], None);
        let completion = expect_completion(outcome);
        assert_eq!(
            process_invocation(&completion).0,
            strings(&["completion", "--shell", "bash"]).as_slice()
        );
        assert_eq!(completion.recipe.source, NativeRecipeSource::HelpEvidenced);

        let joined = temp.path().join("demo-joined");
        write_case_executable(
            &joined,
            &[
                (strings(&["--help"]), root_help.to_string()),
                (strings(&["completion", "--help"]), nested_help.to_string()),
                (strings(&["completion", "--shell=bash"]), payload),
            ],
        );
        let (outcome, _) = run_managed_plan(CompletionShell::Bash, &joined, bin, &[], &[], None);
        let completion = expect_completion(outcome);
        assert_eq!(
            process_invocation(&completion).0,
            strings(&["completion", "--shell=bash"]).as_slice()
        );
        assert_eq!(completion.recipe.source, NativeRecipeSource::HelpEvidenced);
    });
}

#[test]
fn powershell_protocol_accepts_powershell_and_pwsh_synonyms() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        write_case_executable(
            &command,
            &[(
                strings(&["completion", "pwsh"]),
                valid_payload(CompletionShell::PowerShell, "demo"),
            )],
        );
        let (outcome, attempts) =
            run_managed_plan(CompletionShell::PowerShell, &command, bin, &[], &[], None);
        let completion = expect_completion(outcome);
        assert_eq!(attempts, 2, "powershell must be attempted before pwsh");
        assert_eq!(
            process_invocation(&completion).0,
            strings(&["completion", "pwsh"]).as_slice()
        );
    });
}

#[test]
fn click_typer_framework_environment_source_protocol_is_supported() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        let bash_payload = valid_payload(CompletionShell::Bash, "demo");
        let zsh_payload = valid_payload(CompletionShell::Zsh, "demo");
        let fish_payload = valid_payload(CompletionShell::Fish, "demo");
        let script = format!(
            "#!/bin/sh\n\
             if [ \"$#\" -eq 1 ] && [ \"$1\" = \"--help\" ]; then\n\
               printf '%s' {}\n\
               exit 0\n\
             fi\n\
             if [ \"$#\" -eq 0 ] && [ \"${{_DEMO_COMPLETE:-}}\" = \"bash_source\" ]; then\n\
               printf '%s' {}\n\
               exit 0\n\
             fi\n\
             if [ \"$#\" -eq 0 ] && [ \"${{_DEMO_COMPLETE:-}}\" = \"zsh_source\" ]; then\n\
               printf '%s' {}\n\
               exit 0\n\
             fi\n\
             if [ \"$#\" -eq 0 ] && [ \"${{_DEMO_COMPLETE:-}}\" = \"fish_source\" ]; then\n\
               printf '%s' {}\n\
               exit 0\n\
             fi\n\
             exit 1\n",
            sh_single_quote(
                "Usage: demo [OPTIONS]\nOptions:\n  --help  Show this message and exit.\n"
            ),
            sh_single_quote(&bash_payload),
            sh_single_quote(&zsh_payload),
            sh_single_quote(&fish_payload),
        );
        write_executable(&command, &script).unwrap();

        for (shell, source_mode) in [
            (CompletionShell::Bash, "bash_source"),
            (CompletionShell::Zsh, "zsh_source"),
            (CompletionShell::Fish, "fish_source"),
        ] {
            let (outcome, _) = run_managed_plan(shell, &command, bin, &[], &[], None);
            let completion = expect_completion(outcome);
            let (_, recipe_env) = process_invocation(&completion);
            assert_eq!(
                completion.recipe.source,
                NativeRecipeSource::FrameworkEnvironment
            );
            assert_eq!(
                recipe_env.get("_DEMO_COMPLETE").map(String::as_str),
                Some(source_mode)
            );
        }
        assert!(framework_environment_recipes(CompletionShell::Elvish, "demo").is_empty());
        assert!(framework_environment_recipes(CompletionShell::PowerShell, "demo").is_empty());
    });
}

#[test]
fn declarative_catalog_recipe_supports_nonstandard_generator() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        let expected = strings(&["emit-native", "--target", "bash", "--command", "demo"]);
        write_case_executable(
            &command,
            &[(
                expected.clone(),
                valid_payload(CompletionShell::Bash, "demo"),
            )],
        );
        let catalog = vec![RegistryCompletionRecipe {
            id: Some("nonstandard".to_string()),
            shells: vec!["bash".to_string()],
            args: strings(&[
                "emit-native",
                "--target",
                "{shell}",
                "--command",
                "{command}",
            ]),
            env: BTreeMap::new(),
        }];
        let (outcome, attempts) =
            run_managed_plan(CompletionShell::Bash, &command, bin, &[], &catalog, None);
        let completion = expect_completion(outcome);
        assert_eq!(attempts, 1);
        assert_eq!(completion.recipe.source, NativeRecipeSource::Catalog);
        assert_eq!(process_invocation(&completion).0, expected.as_slice());
    });
}

#[test]
fn declarative_catalog_native_schema_deserializes_and_validates() {
    let registry: crate::completions::registry::Registry = serde_json::from_str(
        r#"{
          "schema_version": 1,
          "tools": [{
            "name": "demo",
            "provider": "path",
            "trust_dynamic": true,
            "bundled_completions": [{
              "id": "fish-static",
              "shell": "fish",
              "path": "share/completions/demo.fish"
            }],
            "completion_recipes": [{
              "id": "nonstandard",
              "shells": ["pwsh"],
              "argv": ["emit-native", "--target", "{shell}"],
              "env": {"DEMO_MODE": "source"}
            }]
          }]
        }"#,
    )
    .unwrap();
    let tool = &registry.tools[0];
    validate_catalog_native_tool(tool).unwrap();
    assert!(tool.trust_dynamic);
    assert_eq!(tool.bundled_completions[0].shell, "fish");
    assert_eq!(
        tool.completion_recipes[0].args,
        strings(&["emit-native", "--target", "{shell}"])
    );
}

#[test]
fn provider_bundled_static_artifact_precedes_process_recipes() {
    with_isolated_environment(|temp, bin| {
        let command = bin.join("demo-command");
        let marker = temp.path().join("process-was-invoked");
        let script = format!(
            "#!/bin/sh\nprintf invoked > {}\nexit 91\n",
            sh_single_quote(&marker.display().to_string())
        );
        write_executable(&command, &script).unwrap();
        let artifact_dir = bin.join("completions");
        fs::create_dir_all(&artifact_dir).unwrap();
        let artifact = artifact_dir.join("demo.bash");
        let payload = valid_payload(CompletionShell::Bash, "demo");
        fs::write(&artifact, &payload).unwrap();
        let bundled = vec![RegistryBundledCompletion {
            shell: "bash".to_string(),
            path: "completions/demo.bash".to_string(),
            id: Some("provider-static".to_string()),
        }];
        let catalog = vec![RegistryCompletionRecipe {
            id: Some("should-not-run".to_string()),
            shells: vec!["bash".to_string()],
            args: strings(&["emit-completion"]),
            env: BTreeMap::new(),
        }];
        let (outcome, attempts) = run_managed_plan(
            CompletionShell::Bash,
            &command,
            bin,
            &bundled,
            &catalog,
            None,
        );
        let completion = expect_completion(outcome);
        assert_eq!(attempts, 1);
        assert_eq!(completion.bytes, payload.into_bytes());
        assert_eq!(
            completion.recipe.source,
            NativeRecipeSource::ProviderBundledStatic
        );
        assert!(!marker.exists());
    });
}

#[test]
fn bundled_artifact_identity_enforces_fixed_byte_bound() {
    with_isolated_environment(|_temp, bin| {
        let command_path = bin.join("demo-command");
        write_executable(&command_path, "#!/bin/sh\nexit 1\n").unwrap();
        let completion_dir = bin.join("completions");
        fs::create_dir_all(&completion_dir).unwrap();
        let artifact = completion_dir.join("demo.bash");
        fs::File::create(&artifact)
            .unwrap()
            .set_len(MAX_BUNDLED_ARTIFACT_IDENTITY_BYTES + 1)
            .unwrap();
        let command = CompletionCommandSpec {
            program: command_path,
            args: Vec::new(),
        };
        let bundled = vec![RegistryBundledCompletion {
            shell: "bash".to_string(),
            path: "completions/demo.bash".to_string(),
            id: Some("bounded-provider-artifact".to_string()),
        }];

        let error = provider_bundled_artifact_identity(
            CompletionShell::Bash,
            "demo",
            &command,
            bin,
            &bundled,
        )
        .unwrap_err();
        assert!(error.starts_with(
            "native_bundled_artifact_identity_limit_exceeded:bounded-provider-artifact:"
        ));
    });
}

#[test]
fn previous_successful_recipe_precedes_catalog_and_registry_probes() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        let bad_marker = temp.path().join("bad-catalog-recipe-ran");
        let payload = valid_payload(CompletionShell::Bash, "demo");
        let script = format!(
            "#!/bin/sh\n\
             if [ \"${{1:-}}\" = \"native\" ] && [ \"${{2:-}}\" = \"bad\" ]; then\n\
               printf bad > {}\n\
               exit 92\n\
             fi\n\
             if [ \"${{1:-}}\" = \"native\" ] && [ \"${{2:-}}\" = \"good\" ]; then\n\
               printf '%s' {}\n\
               exit 0\n\
             fi\n\
             exit 1\n",
            sh_single_quote(&bad_marker.display().to_string()),
            sh_single_quote(&payload),
        );
        write_executable(&command, &script).unwrap();
        let catalog = vec![
            RegistryCompletionRecipe {
                id: Some("bad".to_string()),
                shells: vec!["bash".to_string()],
                args: strings(&["native", "bad"]),
                env: BTreeMap::new(),
            },
            RegistryCompletionRecipe {
                id: Some("good".to_string()),
                shells: vec!["bash".to_string()],
                args: strings(&["native", "good"]),
                env: BTreeMap::new(),
            },
        ];
        let previous = NativeRecipeMemo {
            protocol_registry_version: NATIVE_PROTOCOL_REGISTRY_VERSION,
            id: "good".to_string(),
            source: NativeRecipeSource::Catalog,
            shell: "bash".to_string(),
            command: "demo".to_string(),
            invocation: NativeRecipeInvocation::Process {
                args: strings(&["native", "good"]),
                env: BTreeMap::new(),
            },
        };
        let (outcome, attempts) = run_managed_plan(
            CompletionShell::Bash,
            &command,
            bin,
            &[],
            &catalog,
            Some(&previous),
        );
        let completion = expect_completion(outcome);
        assert_eq!(attempts, 1);
        assert_eq!(completion.recipe.id, "good");
        assert!(!bad_marker.exists());
    });
}

#[test]
fn wrong_command_registration_is_rejected_for_all_five_shells() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        let shells = [
            (CompletionShell::Bash, "bash"),
            (CompletionShell::Zsh, "zsh"),
            (CompletionShell::Fish, "fish"),
            (CompletionShell::Elvish, "elvish"),
            (CompletionShell::PowerShell, "powershell"),
        ];
        let cases = shells
            .iter()
            .map(|(shell, shell_name)| {
                (
                    strings(&["native", *shell_name]),
                    valid_payload(*shell, "other"),
                )
            })
            .collect::<Vec<_>>();
        write_case_executable(&command, &cases);
        let catalog = vec![RegistryCompletionRecipe {
            id: Some("wrong-command".to_string()),
            shells: Vec::new(),
            args: strings(&["native", "{shell}"]),
            env: BTreeMap::new(),
        }];

        for (shell, _) in shells {
            let (outcome, _) = run_managed_plan(shell, &command, bin, &[], &catalog, None);
            let diagnostics = expect_not_found(outcome);
            assert!(
                diagnostics
                    .summary()
                    .contains("native_registration_wrong_command:expected=demo:found=other"),
                "{}: {:?}",
                shell.as_event_name(),
                diagnostics.rejections
            );
        }
    });
}

#[test]
fn leading_banner_is_rejected_without_rewriting_payload() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        let output = format!(
            "Generating completion for demo...\n{}",
            valid_payload(CompletionShell::Bash, "demo")
        );
        write_case_executable(&command, &[(strings(&["native"]), output)]);
        let catalog = vec![RegistryCompletionRecipe {
            id: Some("banner".to_string()),
            shells: vec!["bash".to_string()],
            args: strings(&["native"]),
            env: BTreeMap::new(),
        }];
        let (outcome, _) =
            run_managed_plan(CompletionShell::Bash, &command, bin, &[], &catalog, None);
        let diagnostics = expect_not_found(outcome);
        assert!(diagnostics
            .summary()
            .contains("native_output_leading_banner"));
    });
}

#[test]
fn bom_crlf_and_terminal_newline_are_canonicalized() {
    with_isolated_environment(|temp, bin| {
        let command = bin.join("demo-command");
        write_executable(&command, "#!/bin/sh\nexit 1\n").unwrap();
        let artifact_dir = bin.join("completions");
        fs::create_dir_all(&artifact_dir).unwrap();
        let artifact = artifact_dir.join("demo.bash");
        let expected = valid_payload(CompletionShell::Bash, "demo");
        let mut raw = vec![0xef, 0xbb, 0xbf];
        raw.extend_from_slice(expected.replace('\n', "\r\n").as_bytes());
        raw.extend_from_slice(b"\r\n\r\n");
        fs::write(&artifact, raw).unwrap();
        let bundled = vec![RegistryBundledCompletion {
            shell: "bash".to_string(),
            path: "completions/demo.bash".to_string(),
            id: None,
        }];
        let (outcome, _) =
            run_managed_plan(CompletionShell::Bash, &command, bin, &bundled, &[], None);
        let completion = expect_completion(outcome);
        assert_eq!(completion.bytes, expected.into_bytes());
        assert_eq!(completion.bytes.last(), Some(&b'\n'));
        assert!(!completion.bytes.ends_with(b"\n\n"));
    });
}

#[test]
fn narrowly_declarative_bash_payload_is_static_without_dynamic_trust() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        let payload = "# generated completion\ncomplete -W 'alpha beta' demo\n";
        write_case_executable(
            &command,
            &[(strings(&["completion", "bash"]), payload.to_string())],
        );
        let (outcome, attempts) = run_plan(
            CompletionShell::Bash,
            &command,
            &[],
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Ambient,
            false,
            limits(),
        );
        let completion = expect_completion(outcome);
        assert_eq!(attempts, 1);
        assert_eq!(
            completion.classification,
            CompletionArtifactClassification::Static
        );
    });
}

#[test]
fn ambient_evasive_function_body_requires_dynamic_trust() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        write_case_executable(
            &command,
            &[(
                strings(&["completion", "bash"]),
                evasive_dynamic_bash_payload("demo"),
            )],
        );

        let (rejected, rejected_attempts) = run_plan(
            CompletionShell::Bash,
            &command,
            &[],
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Ambient,
            false,
            limits(),
        );
        assert_eq!(
            rejected.unwrap_err(),
            "native_policy_rejected:ambient_dynamic_requires_explicit_trust"
        );
        assert_eq!(rejected_attempts, 1);

        let (accepted, accepted_attempts) = run_plan(
            CompletionShell::Bash,
            &command,
            &[],
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Ambient,
            true,
            limits(),
        );
        let completion = expect_completion(accepted);
        assert_eq!(accepted_attempts, 1);
        assert_eq!(
            completion.classification,
            CompletionArtifactClassification::Dynamic
        );
    });
}

#[test]
fn provider_managed_dynamic_native_output_is_allowed() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        write_case_executable(
            &command,
            &[(
                strings(&["completion", "bash"]),
                dynamic_bash_payload("demo"),
            )],
        );
        let (outcome, _) = run_plan(
            CompletionShell::Bash,
            &command,
            &[],
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Managed,
            false,
            limits(),
        );
        let completion = expect_completion(outcome);
        assert_eq!(
            completion.classification,
            CompletionArtifactClassification::Dynamic
        );
    });
}

#[test]
fn explicit_catalog_dynamic_native_output_is_allowed() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        write_case_executable(
            &command,
            &[(strings(&["explicit-native"]), dynamic_bash_payload("demo"))],
        );
        let catalog = vec![RegistryCompletionRecipe {
            id: Some("explicit-dynamic".to_string()),
            shells: vec!["bash".to_string()],
            args: strings(&["explicit-native"]),
            env: BTreeMap::new(),
        }];
        let (outcome, _) = run_plan(
            CompletionShell::Bash,
            &command,
            &[],
            bin,
            &[],
            &catalog,
            None,
            NativeCandidateOrigin::Ambient,
            false,
            limits(),
        );
        let completion = expect_completion(outcome);
        assert_eq!(completion.recipe.source, NativeRecipeSource::Catalog);
        assert_eq!(
            completion.classification,
            CompletionArtifactClassification::Dynamic
        );
    });
}

#[test]
fn ambient_dynamic_native_output_requires_explicit_trust() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        write_case_executable(
            &command,
            &[(
                strings(&["completion", "bash"]),
                dynamic_bash_payload("demo"),
            )],
        );
        let (outcome, attempts) = run_plan(
            CompletionShell::Bash,
            &command,
            &[],
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Ambient,
            false,
            limits(),
        );
        let error = outcome.unwrap_err();
        assert_eq!(
            error,
            "native_policy_rejected:ambient_dynamic_requires_explicit_trust"
        );
        assert_eq!(attempts, 1, "policy rejection must stop probing");
    });
}

#[test]
fn ambient_dynamic_policy_rejection_never_falls_back_to_help() {
    with_isolated_environment(|temp, bin| {
        let command_path = temp.path().join("demo-command");
        let help_marker = temp.path().join("help-was-probed");
        let payload = dynamic_zsh_payload("demo");
        let script = format!(
            "#!/bin/sh\n\
             if [ \"${{1:-}}\" = completion ] && [ \"${{2:-}}\" = zsh ]; then\n\
               printf '%s' {}\n\
               exit 0\n\
             fi\n\
             if [ \"${{1:-}}\" = --help ]; then\n\
               printf probed > {}\n\
               printf '%s\\n' 'Usage: demo [OPTIONS]' 'Options:' '  --help  Show help'\n\
               exit 0\n\
             fi\n\
             exit 1\n",
            sh_single_quote(&payload),
            sh_single_quote(&help_marker.display().to_string()),
        );
        write_executable(&command_path, &script).unwrap();
        let command = CompletionCommandSpec {
            program: command_path,
            args: Vec::new(),
        };
        let rc_root = temp.path().join("rc-root");
        let mut session = NativeProbeSession::with_limits(limits());
        let result = generate_tool_completion(
            CompletionGenerationRequest {
                provider: "path",
                tool: "demo",
                shell: CompletionShell::Zsh,
                rc_root: &rc_root,
                command: &command,
                provider_bin_dir: bin,
                bundled_completions: &[],
                catalog_recipes: &[],
                previous_recipe: None,
                origin: NativeCandidateOrigin::Ambient,
                trust_dynamic: false,
            },
            &mut session,
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("ambient dynamic output unexpectedly reached help fallback"),
        };
        assert_eq!(
            error,
            "native_policy_rejected:ambient_dynamic_requires_explicit_trust"
        );
        assert_eq!(session.attempts_used(), 1);
        assert!(!help_marker.exists());
        assert!(!rc_root.exists());
    });
}

#[test]
fn ambient_dynamic_native_output_is_allowed_with_explicit_trust() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        write_case_executable(
            &command,
            &[(
                strings(&["completion", "bash"]),
                dynamic_bash_payload("demo"),
            )],
        );
        let (outcome, _) = run_plan(
            CompletionShell::Bash,
            &command,
            &[],
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Ambient,
            true,
            limits(),
        );
        let completion = expect_completion(outcome);
        assert_eq!(
            completion.classification,
            CompletionArtifactClassification::Dynamic
        );
    });
}

#[test]
fn shell_syntax_failure_rejects_native_output() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        let validator_marker = temp.path().join("validator-ran");
        write_case_executable(
            &command,
            &[(
                strings(&["native"]),
                valid_payload(CompletionShell::Bash, "demo"),
            )],
        );
        let validator = format!(
            "#!/bin/sh\nprintf invalid > {}\nexit 1\n",
            sh_single_quote(&validator_marker.display().to_string())
        );
        write_executable(&bin.join("bash"), &validator).unwrap();
        let catalog = vec![RegistryCompletionRecipe {
            id: Some("syntax-failure".to_string()),
            shells: vec!["bash".to_string()],
            args: strings(&["native"]),
            env: BTreeMap::new(),
        }];
        let (outcome, _) =
            run_managed_plan(CompletionShell::Bash, &command, bin, &[], &catalog, None);
        let diagnostics = expect_not_found(outcome);
        assert!(diagnostics
            .summary()
            .contains("native_syntax_validation_failed:bash"));
        assert!(validator_marker.exists());
    });
}

#[test]
fn bounded_runner_uses_exact_executable_direct_argv_closed_stdin_and_controlled_environment() {
    with_isolated_environment(|temp, bin| {
        let _secret = EnvVarGuard::set("UNCONTROLLED_NATIVE_SECRET", "must-not-leak");
        let command = temp.path().join("exact-demo-command");
        let payload = valid_payload(CompletionShell::Bash, "demo");
        let script = format!(
            "#!/bin/sh\n\
             [ \"${{UNCONTROLLED_NATIVE_SECRET+x}}\" != x ] || exit 90\n\
             [ \"${{EXPLICIT_COMPLETION_ENV:-}}\" = ok ] || exit 91\n\
             [ \"${{1:-}}\" = launch-prefix ] || exit 92\n\
             [ \"${{2:-}}\" = explicit-recipe ] || exit 93\n\
             if IFS= read -r line; then exit 94; fi\n\
             printf '%s' {}\n",
            sh_single_quote(&payload)
        );
        write_executable(&command, &script).unwrap();
        let mut recipe_env = BTreeMap::new();
        recipe_env.insert("EXPLICIT_COMPLETION_ENV".to_string(), "ok".to_string());
        let catalog = vec![RegistryCompletionRecipe {
            id: Some("runner-contract".to_string()),
            shells: vec!["bash".to_string()],
            args: strings(&["explicit-recipe"]),
            env: recipe_env,
        }];
        let (outcome, attempts) = run_plan(
            CompletionShell::Bash,
            &command,
            &strings(&["launch-prefix"]),
            bin,
            &[],
            &catalog,
            None,
            NativeCandidateOrigin::Managed,
            false,
            limits(),
        );
        let completion = expect_completion(outcome);
        assert_eq!(attempts, 1);
        assert_eq!(completion.bytes, payload.into_bytes());
    });
}

#[test]
fn native_probe_timeout_is_bounded() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        write_executable(&command, "#!/bin/sh\n/bin/sleep 5\nexit 1\n").unwrap();
        let probe_limits = NativeProbeLimits {
            per_probe_timeout: Duration::from_millis(50),
            total_timeout: Duration::from_secs(2),
            ..limits()
        };
        let (outcome, _) = run_plan(
            CompletionShell::Bash,
            &command,
            &[],
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Managed,
            false,
            probe_limits,
        );
        let error = outcome.unwrap_err();
        assert!(error.starts_with("native_probe_timeout:"), "{error}");
    });
}

#[test]
fn native_total_deadline_bounds_all_attempts() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        write_executable(&command, "#!/bin/sh\n/bin/sleep 0.06\nexit 1\n").unwrap();
        let probe_limits = NativeProbeLimits {
            per_probe_timeout: Duration::from_millis(500),
            total_timeout: Duration::from_millis(90),
            ..limits()
        };
        let (outcome, _) = run_plan(
            CompletionShell::Bash,
            &command,
            &[],
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Managed,
            false,
            probe_limits,
        );
        assert_eq!(outcome.unwrap_err(), "native_total_deadline_exhausted");
    });
}

#[test]
fn native_attempt_budget_bounds_protocol_search() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        write_executable(&command, "#!/bin/sh\nexit 1\n").unwrap();
        let probe_limits = NativeProbeLimits {
            attempt_limit: 2,
            ..limits()
        };
        let (outcome, attempts) = run_plan(
            CompletionShell::Bash,
            &command,
            &[],
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Managed,
            false,
            probe_limits,
        );
        assert_eq!(outcome.unwrap_err(), "native_attempt_budget_exhausted");
        assert_eq!(attempts, 2);
    });
}

#[test]
fn native_stdout_and_stderr_limits_are_enforced() {
    with_isolated_environment(|temp, bin| {
        let stdout_command = temp.path().join("stdout-command");
        write_executable(
            &stdout_command,
            "#!/bin/sh\nwhile :; do printf '0123456789abcdef'; done\n",
        )
        .unwrap();
        let output_limits = NativeProbeLimits {
            per_probe_timeout: Duration::from_secs(1),
            total_timeout: Duration::from_secs(2),
            stdout_limit: 64,
            stderr_limit: 64,
            ..limits()
        };
        let (outcome, _) = run_plan(
            CompletionShell::Bash,
            &stdout_command,
            &[],
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Managed,
            false,
            output_limits,
        );
        assert!(outcome
            .unwrap_err()
            .starts_with("native_stdout_limit_exceeded:"));

        let stderr_command = temp.path().join("stderr-command");
        write_executable(
            &stderr_command,
            "#!/bin/sh\nwhile :; do printf '0123456789abcdef' >&2; done\n",
        )
        .unwrap();
        let (outcome, _) = run_plan(
            CompletionShell::Bash,
            &stderr_command,
            &[],
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Managed,
            false,
            output_limits,
        );
        assert!(outcome
            .unwrap_err()
            .starts_with("native_stderr_limit_exceeded:"));
    });
}

#[test]
fn native_probe_timeout_terminates_descendants() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        let descendant_marker = temp.path().join("descendant-survived");
        let script = format!(
            "#!/bin/sh\n\
             ( /bin/sleep 1; printf survived > {} ) &\n\
             /bin/sleep 10\n",
            sh_single_quote(&descendant_marker.display().to_string())
        );
        write_executable(&command, &script).unwrap();
        let probe_limits = NativeProbeLimits {
            per_probe_timeout: Duration::from_millis(50),
            total_timeout: Duration::from_secs(2),
            ..limits()
        };
        let (outcome, _) = run_plan(
            CompletionShell::Bash,
            &command,
            &[],
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Managed,
            false,
            probe_limits,
        );
        assert!(outcome.unwrap_err().starts_with("native_probe_timeout:"));
        std::thread::sleep(Duration::from_millis(1_250));
        assert!(
            !descendant_marker.exists(),
            "a descendant survived native probe process-tree termination"
        );
    });
}

#[test]
fn mutating_install_completion_forms_are_never_invoked() {
    with_isolated_environment(|temp, bin| {
        assert!(PROTOCOL_FORMS
            .iter()
            .all(|form| !form.head.value().contains("install")));
        let command = temp.path().join("demo-command");
        let marker = temp.path().join("mutating-command-ran");
        let script = format!(
            "#!/bin/sh\nprintf invoked > {}\nexit 0\n",
            sh_single_quote(&marker.display().to_string())
        );
        write_executable(&command, &script).unwrap();
        let catalog = vec![RegistryCompletionRecipe {
            id: Some("forbidden".to_string()),
            shells: vec!["bash".to_string()],
            args: strings(&["install-completion", "bash"]),
            env: BTreeMap::new(),
        }];
        let (outcome, attempts) =
            run_managed_plan(CompletionShell::Bash, &command, bin, &[], &catalog, None);
        assert_eq!(
            outcome.unwrap_err(),
            "native_mutating_recipe_rejected:install_completion"
        );
        assert_eq!(attempts, 0);
        assert!(!marker.exists());

        let launch_args = strings(&["install-completion"]);
        let (outcome, attempts) = run_plan(
            CompletionShell::Bash,
            &command,
            &launch_args,
            bin,
            &[],
            &[],
            None,
            NativeCandidateOrigin::Managed,
            false,
            limits(),
        );
        assert_eq!(
            outcome.unwrap_err(),
            "native_mutating_recipe_rejected:install_completion"
        );
        assert_eq!(attempts, 0);
        assert!(!marker.exists());
    });
}

#[test]
fn valid_native_completion_stops_before_richer_help() {
    with_isolated_environment(|temp, bin| {
        let command = temp.path().join("demo-command");
        let help_marker = temp.path().join("help-was-probed");
        let payload = valid_payload(CompletionShell::Bash, "demo");
        let script = format!(
            "#!/bin/sh\n\
             if [ \"${{1:-}}\" = completion ] && [ \"${{2:-}}\" = bash ]; then\n\
               printf '%s' {}\n\
               exit 0\n\
             fi\n\
             if [ \"${{1:-}}\" = --help ]; then\n\
               printf probed > {}\n\
               printf '%s\\n' 'Usage: demo [OPTIONS]' 'Options:' '  --richer-help-only  Richer help'\n\
               exit 0\n\
             fi\n\
             exit 1\n",
            sh_single_quote(&payload),
            sh_single_quote(&help_marker.display().to_string()),
        );
        write_executable(&command, &script).unwrap();
        let (outcome, attempts) =
            run_managed_plan(CompletionShell::Bash, &command, bin, &[], &[], None);
        let completion = expect_completion(outcome);
        assert_eq!(attempts, 1);
        assert_eq!(completion.bytes, payload.into_bytes());
        assert!(!help_marker.exists());
    });
}
