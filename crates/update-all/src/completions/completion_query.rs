//! Versioned dependency-free completion query transport and shared engine.
//!
//! Requests use direct argv elements, preserving every character representable by
//! an operating-system argument. Responses are a strict tab-separated envelope
//! whose text fields are lowercase hexadecimal UTF-8, so no shell quoting or line
//! character can alter candidate values, descriptions, or append directives.

use super::help_ir::{CommandNode, CompletionIr, OptionSpec, Repeatability, ValueArity, ValueHint};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub(crate) const QUERY_PROTOCOL: &str = "update-all-completion-query-v1";
pub(crate) const RESPONSE_PROTOCOL: &str = "update-all-completion-response-v1";
pub(crate) const MAX_QUERY_WORDS: usize = 4096;
pub(crate) const MAX_QUERY_TEXT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_RESPONSE_RECORDS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum QueryShell {
    Bash,
    Zsh,
    Fish,
    Elvish,
    PowerShell,
}

impl QueryShell {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            "elvish" => Some(Self::Elvish),
            "powershell" | "pwsh" => Some(Self::PowerShell),
            _ => None,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::Elvish => "elvish",
            Self::PowerShell => "powershell",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QueryRequest {
    pub(crate) shell: QueryShell,
    pub(crate) words: Vec<String>,
    pub(crate) word_index: usize,
    pub(crate) cursor_byte: usize,
}

impl QueryRequest {
    pub(crate) fn current_word(&self) -> &str {
        self.words
            .get(self.word_index)
            .map(String::as_str)
            .unwrap_or("")
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.words.len() > MAX_QUERY_WORDS {
            return Err(invalid("completion query has too many words"));
        }
        let total = self.words.iter().map(String::len).sum::<usize>();
        if total > MAX_QUERY_TEXT_BYTES {
            return Err(invalid("completion query text exceeds the hard bound"));
        }
        if self.word_index > self.words.len() {
            return Err(invalid("completion query word index is out of range"));
        }
        if let Some(current) = self.words.get(self.word_index) {
            if self.cursor_byte > current.len() || !current.is_char_boundary(self.cursor_byte) {
                return Err(invalid("completion query cursor is not a UTF-8 boundary"));
            }
        } else if self.cursor_byte != 0 {
            return Err(invalid(
                "completion query cursor is nonzero beyond the final word",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum CompletionDirective {
    None,
    File,
    Directory,
    Command,
    User,
    Host,
    NoSpace,
    Append(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct CompletionCandidate {
    pub(crate) value: String,
    pub(crate) description: Option<String>,
    pub(crate) directives: BTreeSet<CompletionDirective>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QueryResponse {
    pub(crate) candidates: Vec<CompletionCandidate>,
    pub(crate) fallback_directives: BTreeSet<CompletionDirective>,
}

impl QueryResponse {
    fn empty() -> Self {
        Self {
            candidates: Vec::new(),
            fallback_directives: BTreeSet::new(),
        }
    }

    pub(crate) fn normalize(&mut self) {
        self.candidates.sort();
        self.candidates.dedup();
        if self.candidates.len() > MAX_RESPONSE_RECORDS {
            self.candidates.truncate(MAX_RESPONSE_RECORDS);
        }
    }

    pub(crate) fn encode(&self) -> String {
        let mut normalized = self.clone();
        normalized.normalize();
        let mut output = String::new();
        output.push_str(RESPONSE_PROTOCOL);
        output.push('\n');
        for directive in &normalized.fallback_directives {
            output.push_str("d\t");
            output.push_str(&encode_directive(directive));
            output.push('\n');
        }
        for candidate in &normalized.candidates {
            output.push_str("c\t");
            output.push_str(&hex_encode(candidate.value.as_bytes()));
            output.push('\t');
            output.push_str(
                &candidate
                    .description
                    .as_deref()
                    .map(|value| hex_encode(value.as_bytes()))
                    .unwrap_or_default(),
            );
            output.push('\t');
            let directives = candidate
                .directives
                .iter()
                .map(encode_directive)
                .collect::<Vec<_>>()
                .join(",");
            output.push_str(&directives);
            output.push('\n');
        }
        output
    }

    #[cfg(test)]
    pub(crate) fn decode(input: &str) -> io::Result<Self> {
        let mut lines = input.lines();
        if lines.next() != Some(RESPONSE_PROTOCOL) {
            return Err(invalid("completion response protocol mismatch"));
        }
        let mut response = Self::empty();
        for line in lines {
            let fields: Vec<&str> = line.split('\t').collect();
            match fields.as_slice() {
                ["d", directive] => {
                    response
                        .fallback_directives
                        .insert(decode_directive(directive)?);
                }
                ["c", value, description, directives] => {
                    let value = String::from_utf8(hex_decode(value)?)
                        .map_err(|_| invalid("candidate is not UTF-8"))?;
                    let description = if description.is_empty() {
                        None
                    } else {
                        Some(
                            String::from_utf8(hex_decode(description)?)
                                .map_err(|_| invalid("description is not UTF-8"))?,
                        )
                    };
                    let mut decoded = BTreeSet::new();
                    if !directives.is_empty() {
                        for directive in directives.split(',') {
                            decoded.insert(decode_directive(directive)?);
                        }
                    }
                    response.candidates.push(CompletionCandidate {
                        value,
                        description,
                        directives: decoded,
                    });
                }
                _ => return Err(invalid("malformed completion response record")),
            }
        }
        response.normalize();
        Ok(response)
    }
}

pub(crate) fn query(ir: &CompletionIr, request: &QueryRequest) -> io::Result<QueryResponse> {
    request.validate()?;
    let current = request.current_word();
    let prefix = current.get(..request.cursor_byte).unwrap_or(current);
    let prior_end = request.word_index.min(request.words.len());
    let prior = &request.words[..prior_end];
    let mut node = &ir.root;
    let mut used_options = BTreeSet::new();
    let mut positional_count = 0usize;
    let mut end_of_options = false;
    let mut expect_value: Option<&OptionSpec> = None;

    let mut index = usize::from(!prior.is_empty());
    while index < prior.len() {
        let word = &prior[index];
        if expect_value.take().is_some() {
            index += 1;
            continue;
        }
        if !end_of_options && word == "--" {
            end_of_options = true;
            index += 1;
            continue;
        }
        if !end_of_options && word.starts_with('-') && word != "-" {
            let spelling = word.split_once('=').map(|pair| pair.0).unwrap_or(word);
            if let Some(option) = find_option(node, spelling) {
                used_options.extend(option.spellings.iter().cloned());
                if !word.contains('=') && option.value.arity == ValueArity::Required {
                    expect_value = Some(option);
                }
            }
            index += 1;
            continue;
        }
        if let Some(child) = node.find_child(word) {
            node = child;
            positional_count = 0;
            used_options.clear();
            end_of_options = false;
            index += 1;
            continue;
        }
        positional_count = positional_count.saturating_add(1);
        index += 1;
    }

    if let Some(option) = expect_value {
        return Ok(complete_value(
            &option.value.hint,
            &option.value.choices,
            prefix,
            option.description.as_ref().map(|d| d.text.as_str()),
        ));
    }
    if !end_of_options {
        if let Some((spelling, value_prefix)) = prefix.split_once('=') {
            if let Some(option) = find_option(node, spelling) {
                let mut response = complete_value(
                    &option.value.hint,
                    &option.value.choices,
                    value_prefix,
                    option.description.as_ref().map(|d| d.text.as_str()),
                );
                for candidate in &mut response.candidates {
                    candidate.value = format!("{spelling}={}", candidate.value);
                }
                return Ok(response);
            }
        }
        if prefix.starts_with('-') {
            return Ok(complete_options(node, prefix, &used_options));
        }
    }

    let mut response = QueryResponse::empty();
    if !end_of_options {
        for child in &node.subcommands {
            let Some(name) = child.canonical_path.last() else {
                continue;
            };
            add_named_candidate(
                &mut response,
                name,
                child.description.as_ref().map(|d| d.text.as_str()),
                prefix,
                BTreeSet::new(),
            );
            for alias in &child.aliases {
                add_named_candidate(
                    &mut response,
                    alias,
                    child.description.as_ref().map(|d| d.text.as_str()),
                    prefix,
                    BTreeSet::new(),
                );
            }
        }
        if prefix.is_empty() {
            let option_response = complete_options(node, prefix, &used_options);
            response.candidates.extend(option_response.candidates);
        }
    }

    if let Some(positional) = node.positionals.get(positional_count).or_else(|| {
        node.positionals
            .last()
            .filter(|last| last.repeatability == Repeatability::Repeatable)
    }) {
        let values = complete_value(
            &positional.value.hint,
            &positional.value.choices,
            prefix,
            positional.description.as_ref().map(|d| d.text.as_str()),
        );
        response.candidates.extend(values.candidates);
        response
            .fallback_directives
            .extend(values.fallback_directives);
    }
    response.normalize();
    Ok(response)
}

fn complete_options(node: &CommandNode, prefix: &str, used: &BTreeSet<String>) -> QueryResponse {
    let mut response = QueryResponse::empty();
    for option in &node.options {
        if option.repeatability != Repeatability::Repeatable
            && option
                .spellings
                .iter()
                .any(|spelling| used.contains(spelling))
        {
            continue;
        }
        for spelling in &option.spellings {
            let mut directives = BTreeSet::new();
            let suffix = match option.value.arity {
                ValueArity::Required if spelling.starts_with("--") => "=",
                _ => "",
            };
            if !suffix.is_empty() {
                directives.insert(CompletionDirective::Append(suffix.to_owned()));
                directives.insert(CompletionDirective::NoSpace);
            }
            add_named_candidate(
                &mut response,
                spelling,
                option.description.as_ref().map(|d| d.text.as_str()),
                prefix,
                directives,
            );
        }
    }
    response.normalize();
    response
}

fn complete_value(
    hint: &ValueHint,
    choices: &[String],
    prefix: &str,
    description: Option<&str>,
) -> QueryResponse {
    let mut response = QueryResponse::empty();
    for choice in choices {
        add_named_candidate(&mut response, choice, description, prefix, BTreeSet::new());
    }
    if choices.is_empty() {
        match hint {
            ValueHint::File => {
                response
                    .fallback_directives
                    .insert(CompletionDirective::File);
            }
            ValueHint::Directory => {
                response
                    .fallback_directives
                    .insert(CompletionDirective::Directory);
            }
            ValueHint::Command => {
                response
                    .fallback_directives
                    .insert(CompletionDirective::Command);
            }
            ValueHint::User => {
                response
                    .fallback_directives
                    .insert(CompletionDirective::User);
            }
            ValueHint::Host => {
                response
                    .fallback_directives
                    .insert(CompletionDirective::Host);
            }
            ValueHint::None | ValueHint::Choice | ValueHint::Opaque(_) | ValueHint::Unknown => {}
        }
    }
    response.normalize();
    response
}

fn find_option<'a>(node: &'a CommandNode, spelling: &str) -> Option<&'a OptionSpec> {
    node.options.iter().find(|option| {
        option
            .spellings
            .iter()
            .any(|candidate| candidate == spelling)
    })
}

fn add_named_candidate(
    response: &mut QueryResponse,
    value: &str,
    description: Option<&str>,
    prefix: &str,
    directives: BTreeSet<CompletionDirective>,
) {
    if value.starts_with(prefix) {
        response.candidates.push(CompletionCandidate {
            value: value.to_owned(),
            description: description.map(str::to_owned),
            directives,
        });
    }
}

pub(crate) fn parse_query_args<I>(args: I) -> io::Result<Option<(PathBuf, QueryRequest)>>
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<OsString> = args.into_iter().collect();
    let Some(marker) = args.iter().position(|arg| arg == QUERY_PROTOCOL) else {
        return Ok(None);
    };
    let mut index = marker + 1;
    let ir_path = PathBuf::from(next_utf8(&args, &mut index, "IR path")?);
    let shell = QueryShell::parse(&next_utf8(&args, &mut index, "shell")?)
        .ok_or_else(|| invalid("unknown completion query shell"))?;
    let word_index = next_utf8(&args, &mut index, "word index")?
        .parse::<usize>()
        .map_err(|_| invalid("invalid completion query word index"))?;
    let cursor_byte = next_utf8(&args, &mut index, "cursor byte")?
        .parse::<usize>()
        .map_err(|_| invalid("invalid completion query cursor"))?;
    if args.get(index).and_then(|arg| arg.to_str()) != Some("--") {
        return Err(invalid("completion query is missing the argv separator"));
    }
    index += 1;
    let mut words = Vec::new();
    while let Some(arg) = args.get(index) {
        words.push(
            arg.to_str()
                .ok_or_else(|| invalid("completion query words must be UTF-8"))?
                .to_owned(),
        );
        index += 1;
    }
    let request = QueryRequest {
        shell,
        words,
        word_index,
        cursor_byte,
    };
    request.validate()?;
    Ok(Some((ir_path, request)))
}

fn next_utf8(args: &[OsString], index: &mut usize, field: &'static str) -> io::Result<String> {
    let value = args.get(*index).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("completion query is missing {field}"),
        )
    })?;
    *index += 1;
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("completion query metadata must be UTF-8"))
}
pub(crate) fn run_from_env() -> Option<i32> {
    match parse_query_args(std::env::args_os()) {
        Ok(None) => None,
        Ok(Some((ir_path, request))) => Some(
            match run_query_file(&ir_path, &request, &mut io::stdout()) {
                Ok(()) => 0,
                Err(error) => {
                    let _ = writeln!(io::stderr(), "update-all completion query failed: {error}");
                    2
                }
            },
        ),
        Err(error) => {
            let _ = writeln!(
                io::stderr(),
                "update-all completion query rejected: {error}"
            );
            Some(2)
        }
    }
}

fn run_query_file(path: &Path, request: &QueryRequest, output: &mut dyn Write) -> io::Result<()> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > super::help_ir::MAX_IR_BYTES as u64 {
        return Err(invalid(
            "completion IR query path is not a bounded regular file",
        ));
    }
    let bytes = fs::read(path)?;
    let ir = CompletionIr::decode(&bytes)?;
    output.write_all(query(&ir, request)?.encode().as_bytes())
}

fn encode_directive(value: &CompletionDirective) -> String {
    match value {
        CompletionDirective::None => "none".into(),
        CompletionDirective::File => "file".into(),
        CompletionDirective::Directory => "directory".into(),
        CompletionDirective::Command => "command".into(),
        CompletionDirective::User => "user".into(),
        CompletionDirective::Host => "host".into(),
        CompletionDirective::NoSpace => "nospace".into(),
        CompletionDirective::Append(value) => format!("append:{}", hex_encode(value.as_bytes())),
    }
}

#[cfg(test)]
fn decode_directive(value: &str) -> io::Result<CompletionDirective> {
    match value {
        "none" => Ok(CompletionDirective::None),
        "file" => Ok(CompletionDirective::File),
        "directory" => Ok(CompletionDirective::Directory),
        "command" => Ok(CompletionDirective::Command),
        "user" => Ok(CompletionDirective::User),
        "host" => Ok(CompletionDirective::Host),
        "nospace" => Ok(CompletionDirective::NoSpace),
        _ if value.starts_with("append:") => {
            let bytes = hex_decode(&value[7..])?;
            String::from_utf8(bytes)
                .map(CompletionDirective::Append)
                .map_err(|_| invalid("append directive is not UTF-8"))
        }
        _ => Err(invalid("unknown completion directive")),
    }
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
pub(crate) fn hex_decode(value: &str) -> io::Result<Vec<u8>> {
    if value.len() % 2 != 0 || value.len() > MAX_QUERY_TEXT_BYTES.saturating_mul(2) {
        return Err(invalid("invalid completion transport hexadecimal length"));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = from_hex(pair[0])?;
        let low = from_hex(pair[1])?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

#[cfg(test)]
fn from_hex(value: u8) -> io::Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(invalid(
            "invalid lowercase hexadecimal completion transport",
        )),
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completions::help_ir::{parse_help, EvidenceRef};

    fn ir() -> CompletionIr {
        let evidence = EvidenceRef {
            digest: "00".repeat(32),
            argv: vec!["--help".into()],
            exit_code: Some(0),
            truncated_stdout: false,
            truncated_stderr: false,
        };
        let mut ir = CompletionIr::new("tool".into(), evidence);
        ir.root = parse_help(b"Usage: tool [OPTIONS] <FILE>\n\nCommands:\n  run  run it\n  stop stop it\n\nOptions:\n  --mode <MODE>  {fast,safe}\n  -v, --verbose  verbose\n\nArguments:\n  <FILE>  input file path\n", &["tool".into()], 0);
        ir
    }

    #[test]
    fn transport_round_trips_arbitrary_shell_characters() {
        let weird = "space tab\tline\nquote'\"$`\\;|&()[]{}🙂";
        let mut response = QueryResponse::empty();
        let mut directives = BTreeSet::new();
        directives.insert(CompletionDirective::Append(weird.into()));
        response.candidates.push(CompletionCandidate {
            value: weird.into(),
            description: Some(weird.into()),
            directives,
        });
        let decoded = QueryResponse::decode(&response.encode()).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn query_preserves_choices_descriptions_and_append_directives() {
        let request = QueryRequest {
            shell: QueryShell::Bash,
            words: vec!["tool".into(), "--mode=".into()],
            word_index: 1,
            cursor_byte: 7,
        };
        let response = query(&ir(), &request).unwrap();
        assert_eq!(response.candidates.len(), 2);
        assert!(response
            .candidates
            .iter()
            .all(|candidate| candidate.description.is_some()));
        let option_request = QueryRequest {
            shell: QueryShell::Fish,
            words: vec!["tool".into(), "--m".into()],
            word_index: 1,
            cursor_byte: 3,
        };
        let option_response = query(&ir(), &option_request).unwrap();
        assert!(option_response.candidates[0]
            .directives
            .contains(&CompletionDirective::Append("=".into())));
    }

    #[test]
    fn unknown_positional_does_not_invent_file_completion() {
        let evidence = EvidenceRef {
            digest: "00".repeat(32),
            argv: vec![],
            exit_code: Some(0),
            truncated_stdout: false,
            truncated_stderr: false,
        };
        let mut ir = CompletionIr::new("tool".into(), evidence);
        ir.root = parse_help(
            b"usage: tool THING\n\npositional arguments:\n  THING  opaque\n",
            &["tool".into()],
            0,
        );
        let response = query(
            &ir,
            &QueryRequest {
                shell: QueryShell::Zsh,
                words: vec!["tool".into(), "".into()],
                word_index: 1,
                cursor_byte: 0,
            },
        )
        .unwrap();
        assert!(!response
            .fallback_directives
            .contains(&CompletionDirective::File));
        assert!(!response
            .fallback_directives
            .contains(&CompletionDirective::Directory));
    }

    #[test]
    fn end_of_options_stops_option_candidates() {
        let response = query(
            &ir(),
            &QueryRequest {
                shell: QueryShell::Elvish,
                words: vec!["tool".into(), "--".into(), "-".into()],
                word_index: 2,
                cursor_byte: 1,
            },
        )
        .unwrap();
        assert!(response
            .candidates
            .iter()
            .all(|candidate| !candidate.value.starts_with('-')));
    }
}
