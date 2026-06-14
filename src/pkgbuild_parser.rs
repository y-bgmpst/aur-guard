use std::path::PathBuf;

use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellWord {
    pub value: String,
    pub line: usize,
    pub dynamic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceLocation {
    Local(PathBuf),
    Remote(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntry {
    pub raw: String,
    pub value: String,
    pub alias: Option<String>,
    pub line: usize,
    pub dynamic: bool,
    pub location: SourceLocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumEntry {
    pub algorithm: String,
    pub value: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallEntry {
    pub path: PathBuf,
    pub raw: String,
    pub line: usize,
    pub dynamic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionBlock {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub body: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pkgbuild {
    pub pkgname: Vec<ShellWord>,
    pub pkgver: Option<ShellWord>,
    pub sources: Vec<SourceEntry>,
    pub checksums: Vec<ChecksumEntry>,
    pub install: Option<InstallEntry>,
    pub functions: Vec<FunctionBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrcInfoEntry {
    pub key: String,
    pub value: String,
    pub line: usize,
}

pub fn parse_pkgbuild(text: &str) -> Pkgbuild {
    let mut parsed = Pkgbuild::default();

    for assignment in collect_assignments(text) {
        if is_source_array(&assignment.name) {
            for word in tokenize_array(&assignment.lines) {
                parsed.sources.push(parse_source_entry(word));
            }
            continue;
        }

        if is_checksum_array(&assignment.name) {
            for word in tokenize_array(&assignment.lines) {
                parsed.checksums.push(ChecksumEntry {
                    algorithm: assignment.name.clone(),
                    value: word.value,
                    line: word.line,
                });
            }
            continue;
        }

        if assignment.name == "pkgname" {
            if assignment.is_array {
                parsed.pkgname.extend(tokenize_array(&assignment.lines));
            } else if let Some(word) = first_word(&assignment.value, assignment.line) {
                parsed.pkgname.push(word);
            }
            continue;
        }

        if assignment.name == "pkgver" {
            if let Some(word) = first_word(&assignment.value, assignment.line) {
                parsed.pkgver = Some(word);
            }
            continue;
        }

        if assignment.name == "install"
            && let Some(word) = first_word(&assignment.value, assignment.line)
        {
            parsed.install = Some(InstallEntry {
                path: PathBuf::from(strip_source_alias(&word.value).1),
                raw: word.value,
                line: word.line,
                dynamic: word.dynamic,
            });
        }
    }

    parsed.functions = parse_functions(text);
    parsed
}

pub fn parse_srcinfo(text: &str) -> Vec<SrcInfoEntry> {
    text.lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some(SrcInfoEntry {
                key: key.trim().to_string(),
                value: value.trim().to_string(),
                line: idx + 1,
            })
        })
        .collect()
}

fn parse_source_entry(word: ShellWord) -> SourceEntry {
    let raw = word.value;
    let (alias, value) = strip_source_alias(&raw);
    let alias = alias.map(ToOwned::to_owned);
    let value = value.to_string();
    let location = if is_remote_url(&value) {
        SourceLocation::Remote(value.clone())
    } else {
        SourceLocation::Local(PathBuf::from(&value))
    };

    SourceEntry {
        raw,
        value,
        alias,
        line: word.line,
        dynamic: word.dynamic,
        location,
    }
}

pub fn is_remote_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.starts_with("ftps://")
        || lower.starts_with("git://")
        || lower.starts_with("ssh://")
        || lower.starts_with("sftp://")
        || lower.starts_with("rsync://")
        || lower.starts_with("scp://")
        || lower.starts_with("git+")
        || lower.starts_with("hg+")
        || lower.starts_with("svn+")
}

pub fn strip_source_alias(value: &str) -> (Option<&str>, &str) {
    match value.split_once("::") {
        Some((alias, source)) if !alias.is_empty() && !source.is_empty() => (Some(alias), source),
        _ => (None, value),
    }
}

pub fn is_vcs_source(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("git+")
        || lower.starts_with("hg+")
        || lower.starts_with("svn+")
        || lower.ends_with(".git")
}

fn is_source_array(name: &str) -> bool {
    name == "source" || name.starts_with("source_")
}

fn is_checksum_array(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "b2sums"
        || lower.starts_with("b2sums_")
        || lower == "md5sums"
        || lower.starts_with("md5sums_")
        || lower == "sha1sums"
        || lower.starts_with("sha1sums_")
        || lower == "sha224sums"
        || lower.starts_with("sha224sums_")
        || lower == "sha256sums"
        || lower.starts_with("sha256sums_")
        || lower == "sha384sums"
        || lower.starts_with("sha384sums_")
        || lower == "sha512sums"
        || lower.starts_with("sha512sums_")
}

#[derive(Debug, Clone)]
struct Assignment {
    name: String,
    value: String,
    line: usize,
    is_array: bool,
    lines: Vec<(usize, String)>,
}

fn collect_assignments(text: &str) -> Vec<Assignment> {
    let assign_re = Regex::new(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$").expect("valid regex");
    let raw_lines = text
        .lines()
        .enumerate()
        .map(|(idx, line)| (idx + 1, line.to_string()))
        .collect::<Vec<_>>();

    let mut assignments = Vec::new();
    let mut idx = 0;
    while idx < raw_lines.len() {
        let (line_no, line) = &raw_lines[idx];
        let Some(caps) = assign_re.captures(line) else {
            idx += 1;
            continue;
        };
        let name = caps.get(1).expect("capture").as_str().to_string();
        let value = caps.get(2).expect("capture").as_str().to_string();
        let starts_array = value.trim_start().starts_with('(');
        let mut lines = vec![(*line_no, value.clone())];

        if starts_array {
            let mut balance = paren_balance(&value);
            while balance > 0 && idx + 1 < raw_lines.len() {
                idx += 1;
                let (next_line_no, next_line) = &raw_lines[idx];
                balance += paren_balance(next_line);
                lines.push((*next_line_no, next_line.clone()));
            }
        }

        assignments.push(Assignment {
            name,
            value,
            line: *line_no,
            is_array: starts_array,
            lines,
        });
        idx += 1;
    }

    assignments
}

fn paren_balance(line: &str) -> i32 {
    let mut balance = 0;
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut prev = '\0';

    for ch in line.chars() {
        if escaped {
            escaped = false;
            prev = ch;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            prev = ch;
            continue;
        }
        if ch == '\'' && !double {
            single = !single;
        } else if ch == '"' && !single {
            double = !double;
        } else if !single && !double {
            if ch == '#' {
                break;
            }
            if ch == '(' && prev != '$' {
                balance += 1;
            } else if ch == ')' {
                balance -= 1;
            }
        }
        prev = ch;
    }

    balance
}

fn first_word(value: &str, line: usize) -> Option<ShellWord> {
    tokenize_words([(line, value.to_string())])
        .into_iter()
        .next()
}

fn tokenize_array(lines: &[(usize, String)]) -> Vec<ShellWord> {
    let mut stripped = Vec::with_capacity(lines.len());
    let mut started = false;
    for (line_no, line) in lines {
        let mut part = line.as_str();
        if !started && let Some(pos) = part.find('(') {
            part = &part[pos + 1..];
            started = true;
        }
        if started {
            stripped.push((*line_no, part.to_string()));
        }
    }
    tokenize_words(stripped)
}

fn tokenize_words<I>(lines: I) -> Vec<ShellWord>
where
    I: IntoIterator<Item = (usize, String)>,
{
    let mut words = Vec::new();
    let mut current = String::new();
    let mut raw = String::new();
    let mut word_line = 0;
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut in_word = false;

    for (line_no, line) in lines {
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if escaped {
                current.push(ch);
                raw.push(ch);
                escaped = false;
                in_word = true;
                if word_line == 0 {
                    word_line = line_no;
                }
                continue;
            }

            if !single && ch == '\\' {
                escaped = true;
                raw.push(ch);
                in_word = true;
                if word_line == 0 {
                    word_line = line_no;
                }
                continue;
            }

            if !single && !double && ch == '#' {
                break;
            }

            if !single && !double && ch == ')' {
                finish_word(
                    &mut words,
                    &mut current,
                    &mut raw,
                    &mut word_line,
                    &mut in_word,
                );
                continue;
            }

            if !single && !double && ch.is_whitespace() {
                finish_word(
                    &mut words,
                    &mut current,
                    &mut raw,
                    &mut word_line,
                    &mut in_word,
                );
                continue;
            }

            if ch == '\'' && !double {
                single = !single;
                raw.push(ch);
                in_word = true;
                if word_line == 0 {
                    word_line = line_no;
                }
                continue;
            }

            if ch == '"' && !single {
                double = !double;
                raw.push(ch);
                in_word = true;
                if word_line == 0 {
                    word_line = line_no;
                }
                continue;
            }

            current.push(ch);
            raw.push(ch);
            in_word = true;
            if word_line == 0 {
                word_line = line_no;
            }

            if chars.peek().is_none() {
                current.push('\n');
                raw.push('\n');
            }
        }

        if !single && !double {
            finish_word(
                &mut words,
                &mut current,
                &mut raw,
                &mut word_line,
                &mut in_word,
            );
        }
    }

    finish_word(
        &mut words,
        &mut current,
        &mut raw,
        &mut word_line,
        &mut in_word,
    );
    words
}

fn finish_word(
    words: &mut Vec<ShellWord>,
    current: &mut String,
    raw: &mut String,
    word_line: &mut usize,
    in_word: &mut bool,
) {
    if !*in_word {
        return;
    }

    let value = current.trim_end_matches('\n').to_string();
    let raw_value = raw.trim_end_matches('\n').to_string();
    if !value.is_empty() {
        words.push(ShellWord {
            value,
            line: (*word_line).max(1),
            dynamic: raw_value.contains("$(")
                || raw_value.contains('`')
                || raw_value.contains("${")
                || raw_value.contains("$pkgver")
                || raw_value.contains("$pkgname"),
        });
    }
    current.clear();
    raw.clear();
    *word_line = 0;
    *in_word = false;
}

fn parse_functions(text: &str) -> Vec<FunctionBlock> {
    let function_re = Regex::new(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{")
        .expect("valid regex");
    let lines = text.lines().collect::<Vec<_>>();
    let mut functions = Vec::new();
    let mut idx = 0;

    while idx < lines.len() {
        let line = lines[idx];
        let Some(caps) = function_re.captures(line) else {
            idx += 1;
            continue;
        };
        let name = caps.get(1).expect("capture").as_str().to_string();
        let start = idx + 1;
        let mut depth = brace_balance(line);
        let mut body = String::new();
        body.push_str(line);
        body.push('\n');

        while depth > 0 && idx + 1 < lines.len() {
            idx += 1;
            let next = lines[idx];
            depth += brace_balance(next);
            body.push_str(next);
            body.push('\n');
        }

        functions.push(FunctionBlock {
            name,
            start_line: start,
            end_line: idx + 1,
            body,
        });
        idx += 1;
    }

    functions
}

fn brace_balance(line: &str) -> i32 {
    let mut balance = 0;
    let mut single = false;
    let mut double = false;
    let mut escaped = false;

    for ch in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '\'' && !double {
            single = !single;
        } else if ch == '"' && !single {
            double = !double;
        } else if !single && !double {
            if ch == '#' {
                break;
            }
            if ch == '{' {
                balance += 1;
            } else if ch == '}' {
                balance -= 1;
            }
        }
    }

    balance
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn parses_sources_checksums_and_install() {
        let parsed = parse_pkgbuild(
            r#"
pkgname=demo
pkgver=1.2.3
install='demo.install'
source=("demo.patch" "bin::https://example.invalid/bin")
sha256sums=('SKIP'
            'abc')
pkgver() {
  git describe --tags
}
"#,
        );

        assert_eq!(parsed.pkgname[0].value, "demo");
        assert_eq!(parsed.pkgver.as_ref().unwrap().value, "1.2.3");
        assert_eq!(parsed.install.as_ref().unwrap().raw, "demo.install");
        assert_eq!(parsed.sources.len(), 2);
        assert_eq!(parsed.sources[1].alias.as_deref(), Some("bin"));
        assert_eq!(parsed.checksums[0].value, "SKIP");
        assert_eq!(parsed.functions[0].name, "pkgver");
    }

    #[test]
    fn marks_dynamic_source_words() {
        let parsed = parse_pkgbuild(r#"source=("https://x/$pkgver/$(uname)")"#);
        assert!(parsed.sources[0].dynamic);
    }

    proptest! {
        #[test]
        fn pkgbuild_parser_does_not_panic(input in "\\PC*") {
            let _ = parse_pkgbuild(&input);
        }
    }
}
