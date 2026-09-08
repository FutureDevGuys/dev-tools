//! Delegate tracked updates before observing the restore/link plan again.
use super::*;

impl App {
    pub(super) fn is_canonical_scope_skill(&self, scope: &str, skill: &InstalledSkill) -> bool {
        let root = if scope == "global" {
            home_dir()
        } else {
            let Ok(root) = std::env::current_dir() else {
                return false;
            };
            root
        };
        if !root.is_absolute() {
            return false;
        }
        let agents = root.join(".agents");
        let skills = agents.join("skills");
        let expected = skills.join(&skill.slug);
        // A provider-listed app cache or symlink to an external installation
        // is not authority for replacing a standalone canonical payload.
        [agents, skills, expected.clone()]
            .iter()
            .all(|path| fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()))
            && fs::symlink_metadata(expected.join("SKILL.md"))
                .is_ok_and(|metadata| metadata.is_file())
            && same_path(Path::new(&skill.path), &expected)
    }

    pub(super) fn prepare_updates(&mut self) -> std::result::Result<(), i32> {
        let mut scopes = Vec::new();
        if self.include_global {
            scopes.push("global");
        }
        if self.include_project {
            scopes.push("project");
        }
        for scope in &scopes {
            let (desired, installed) = if *scope == "global" {
                (&self.payload.global_desired, &self.payload.global_installed)
            } else {
                (
                    &self.payload.project_desired,
                    &self.payload.project_installed,
                )
            };
            let mut names = Vec::new();
            let mut skipped = Vec::new();
            let mut slugs = BTreeSet::new();
            let mut folded = BTreeSet::new();
            for skill in desired {
                if skill.name.is_empty()
                    || skill.name.starts_with('-')
                    || skill.name.chars().any(char::is_control)
                    || !slugs.insert(&skill.slug)
                    || !folded.insert(skill.name.to_lowercase())
                {
                    return Err(self.fail(
                        EXIT_SCHEMA,
                        "tracked skill names are invalid or ambiguous after provider normalization",
                    ));
                }
            }
            for skill in desired {
                let matching = installed
                    .iter()
                    .filter(|item| item.slug == skill.slug)
                    .collect::<Vec<_>>();
                if matching.is_empty() {
                    continue;
                }
                if matching.len() != 1 || !self.is_canonical_scope_skill(scope, matching[0]) {
                    skipped.push(SkippedSkill {
                        scope: (*scope).into(),
                        name: skill.name.clone(),
                        reason: "installed outside the unambiguous canonical skill root; preserved"
                            .into(),
                    });
                    continue;
                }
                if skill.name.is_empty() || skill.name.starts_with('-') || skill.name.contains('\0')
                {
                    return Err(self.fail(
                        EXIT_SCHEMA,
                        "tracked update name cannot be passed unambiguously to the provider",
                    ));
                }
                names.push(skill.name.clone());
            }
            self.payload.skipped.extend(skipped);
            if names.is_empty() {
                continue;
            }
            if names.len() > 4096 || names.iter().map(String::len).sum::<usize>() > 128 * 1024 {
                return Err(self.fail(EXIT_SCHEMA, "tracked update selection exceeds limits"));
            }
            let mut argv = self.options.skills_command.clone();
            argv.extend([
                "update".into(),
                if *scope == "global" {
                    "-g".into()
                } else {
                    "-p".into()
                },
                "-y".into(),
            ]);
            argv.extend(names.clone());
            self.payload.planned_commands.push(AddPlan {
                scope: (*scope).into(),
                reason: "update".into(),
                source: String::new(),
                skills: names,
                agents: Vec::new(),
                command: command_to_string(&argv),
                argv,
            });
        }
        if self.options.dry_run || !self.options.apply || self.payload.planned_commands.is_empty() {
            return Ok(());
        }
        let updates = self.payload.planned_commands.clone();
        // Validate every selected scope before the first mutating provider call.
        for plan in &updates {
            if let Err(error) = self.validate_update_lock(&plan.scope) {
                return Err(self.fail(EXIT_USAGE, &error.to_string()));
            }
        }
        let version = self
            .run_skills(&["--version".into()])
            .map_err(|error| self.fail(EXIT_USAGE, &error.to_string()))?;
        if version.status != 0 || !supports_selected_updates(&version.stdout) {
            return Err(self.fail(EXIT_USAGE, "tracked updates require skills 1.5.25 or newer in the 1.x series; repair does not require the update interface"));
        }
        for plan in updates {
            let arguments = &plan.argv[self.options.skills_command.len()..];
            let result = self
                .run_skills(arguments)
                .map_err(|error| self.fail(EXIT_USAGE, &error.to_string()))?;
            if result.status != 0 {
                return Err(self.fail(EXIT_USAGE, "upstream tracked update failed; later restore and link operations were not run"));
            }
            self.payload.applied.push(AppliedPlan {
                scope: plan.scope.clone(),
                reason: plan.reason,
                source: plan.source,
                skills: plan.skills,
                agents: plan.agents,
                command: plan.command,
            });
            self.refresh_updated_scope(&plan.scope)?;
        }
        Ok(())
    }

    fn validate_update_lock(&self, scope: &str) -> Result<()> {
        let (selected, upstream, observed) = if scope == "global" {
            let selected = self
                .global_lock_selection
                .selected
                .as_ref()
                .ok_or_else(|| anyhow!("selected global update lock is absent"))?
                .path
                .clone();
            (
                selected,
                home_dir().join(".agents/.skill-lock.json"),
                &self.global_lock_selection.lock,
            )
        } else {
            (
                self.project_lock.path.clone(),
                std::env::current_dir()?.join("skills-lock.json"),
                &self.project_lock.lock,
            )
        };
        if !same_path(&selected, &upstream) {
            return Err(anyhow!("updates require the selected lock to be the upstream runtime lock; use repair for a detached desired-state lock"));
        }
        let current = read_lock_file(&upstream, true)?.lock;
        let current = if scope == "global" {
            normalize_global_lock(&current)
        } else {
            current
        };
        if &current != observed {
            return Err(anyhow!("upstream lock changed before tracked update"));
        }
        Ok(())
    }

    fn refresh_updated_scope(&mut self, scope: &str) -> std::result::Result<(), i32> {
        let (path, original) = if scope == "global" {
            (
                PathBuf::from(&self.payload.global_lock_file),
                &self.payload.global_desired,
            )
        } else {
            (
                self.project_lock.path.clone(),
                &self.payload.project_desired,
            )
        };
        let selected = original
            .iter()
            .map(|skill| skill.name.clone())
            .collect::<BTreeSet<_>>();
        let observed = read_lock_file(&path, true)
            .map_err(|error| self.fail(EXIT_USAGE, &error.to_string()))?;
        let mut normalized = normalize_lock_skills(&observed.lock, scope).map_err(|_| {
            self.fail(
                EXIT_SCHEMA,
                "updated upstream lock contains invalid skill entries",
            )
        })?;
        // A provider update is not permission to expand a source selection.
        normalized
            .desired
            .retain(|skill| selected.contains(&skill.name));
        self.payload.skipped.extend(normalized.skipped);
        let installed = self.list_installed(scope)?;
        if scope == "global" {
            self.global_lock_selection.lock = normalize_global_lock(&observed.lock);
            self.payload.global_desired = normalized.desired;
            self.payload.global_installed = installed;
        } else {
            self.project_lock = observed;
            self.payload.project_desired = normalized.desired;
            self.payload.project_installed = installed;
        }
        Ok(())
    }
}

fn supports_selected_updates(text: &str) -> bool {
    let parts = text
        .trim()
        .split('.')
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>();
    matches!(parts.as_deref(), Ok([1, minor, patch]) if (*minor, *patch) >= (5, 25))
}
