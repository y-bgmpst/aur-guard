use std::{env, fs, path::PathBuf, str::FromStr, time::Duration};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputFormat {
    #[default]
    Human,
    Plain,
    Json,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "human" | "terminal" => Ok(Self::Human),
            "plain" | "text" => Ok(Self::Plain),
            "json" => Ok(Self::Json),
            other => Err(format!("unknown output format: {other}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub enabled: bool,
    pub api_key: Option<String>,
    pub base_url: String,
    pub model: String,
    pub token_budget: usize,
    pub max_snippets: usize,
    pub timeout: Duration,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: None,
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-5-mini".to_string(),
            token_budget: 8_000,
            max_snippets: 12,
            timeout: Duration::from_secs(45),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub output: OutputFormat,
    pub warn_only: bool,
    pub keep_tmp: bool,
    pub include_vendored: bool,
    pub fetch_remote_sources: bool,
    pub max_file_bytes: u64,
    pub max_files: usize,
    pub git_timeout: Duration,
    pub llm: LlmConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            output: OutputFormat::Human,
            warn_only: false,
            keep_tmp: false,
            include_vendored: false,
            fetch_remote_sources: false,
            max_file_bytes: 512 * 1024,
            max_files: 2_000,
            git_timeout: Duration::from_secs(45),
            llm: LlmConfig::default(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    output: Option<OutputFormat>,
    warn_only: Option<bool>,
    keep_tmp: Option<bool>,
    include_vendored: Option<bool>,
    fetch_remote_sources: Option<bool>,
    max_file_bytes: Option<u64>,
    max_files: Option<usize>,
    git_timeout_secs: Option<u64>,
    llm: Option<FileLlmConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct FileLlmConfig {
    enabled: Option<bool>,
    api_key: Option<String>,
    base_url: Option<String>,
    model: Option<String>,
    token_budget: Option<usize>,
    max_snippets: Option<usize>,
    timeout_secs: Option<u64>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let mut config = Self::default();

        if let Some(path) = config_path().filter(|path| path.exists()) {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let file_config = toml::from_str::<FileConfig>(&raw)
                .with_context(|| format!("failed to parse {}", path.display()))?;
            config.apply_file(file_config);
        }

        config.apply_env();
        Ok(config)
    }

    fn apply_file(&mut self, file: FileConfig) {
        if let Some(output) = file.output {
            self.output = output;
        }
        apply_bool(&mut self.warn_only, file.warn_only);
        apply_bool(&mut self.keep_tmp, file.keep_tmp);
        apply_bool(&mut self.include_vendored, file.include_vendored);
        apply_bool(&mut self.fetch_remote_sources, file.fetch_remote_sources);
        if let Some(value) = file.max_file_bytes {
            self.max_file_bytes = value;
        }
        if let Some(value) = file.max_files {
            self.max_files = value;
        }
        if let Some(value) = file.git_timeout_secs {
            self.git_timeout = Duration::from_secs(value);
        }

        if let Some(llm) = file.llm {
            apply_bool(&mut self.llm.enabled, llm.enabled);
            if let Some(value) = llm.api_key {
                self.llm.api_key = Some(value);
            }
            if let Some(value) = llm.base_url {
                self.llm.base_url = value;
            }
            if let Some(value) = llm.model {
                self.llm.model = value;
            }
            if let Some(value) = llm.token_budget {
                self.llm.token_budget = value;
            }
            if let Some(value) = llm.max_snippets {
                self.llm.max_snippets = value;
            }
            if let Some(value) = llm.timeout_secs {
                self.llm.timeout = Duration::from_secs(value);
            }
        }
    }

    fn apply_env(&mut self) {
        if let Some(value) = env_output("AUR_GUARD_OUTPUT") {
            self.output = value;
        }
        if let Some(value) = env_bool("AUR_GUARD_WARN_ONLY") {
            self.warn_only = value;
        }
        if let Some(value) = env_bool("AUR_GUARD_KEEP_TMP") {
            self.keep_tmp = value;
        }
        if let Some(value) = env_bool("AUR_GUARD_INCLUDE_VENDORED") {
            self.include_vendored = value;
        }
        if let Some(value) = env_bool("AUR_GUARD_FETCH_REMOTE_SOURCES") {
            self.fetch_remote_sources = value;
        }
        if let Some(value) = env_u64("AUR_GUARD_MAX_FILE_BYTES") {
            self.max_file_bytes = value;
        }
        if let Some(value) = env_usize("AUR_GUARD_MAX_FILES") {
            self.max_files = value;
        }
        if let Some(value) = env_u64("AUR_GUARD_GIT_TIMEOUT_SECS") {
            self.git_timeout = Duration::from_secs(value);
        }

        if let Some(value) = env_bool("AUR_GUARD_LLM") {
            self.llm.enabled = value;
        }
        if let Some(value) =
            env_nonempty("AUR_GUARD_OPENAI_API_KEY").or_else(|| env_nonempty("OPENAI_API_KEY"))
        {
            self.llm.api_key = Some(value);
        }
        if let Some(value) =
            env_nonempty("AUR_GUARD_OPENAI_BASE_URL").or_else(|| env_nonempty("OPENAI_BASE_URL"))
        {
            self.llm.base_url = value;
        }
        if let Some(value) =
            env_nonempty("AUR_GUARD_OPENAI_MODEL").or_else(|| env_nonempty("OPENAI_MODEL"))
        {
            self.llm.model = value;
        }
        if let Some(value) = env_usize("AUR_GUARD_LLM_TOKEN_BUDGET") {
            self.llm.token_budget = value;
        }
        if let Some(value) = env_usize("AUR_GUARD_LLM_MAX_SNIPPETS") {
            self.llm.max_snippets = value;
        }
        if let Some(value) = env_u64("AUR_GUARD_LLM_TIMEOUT_SECS") {
            self.llm.timeout = Duration::from_secs(value);
        }
    }
}

fn apply_bool(target: &mut bool, value: Option<bool>) {
    if let Some(value) = value {
        *target = value;
    }
}

pub fn config_path() -> Option<PathBuf> {
    if let Some(config_home) = env_nonempty("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(config_home).join("aur-guard/config.toml"));
    }

    env::var("HOME")
        .ok()
        .filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".config/aur-guard/config.toml"))
}

fn env_bool(name: &str) -> Option<bool> {
    let value = env::var(name).ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn env_u64(name: &str) -> Option<u64> {
    env::var(name).ok()?.parse().ok()
}

fn env_usize(name: &str) -> Option<usize> {
    env::var(name).ok()?.parse().ok()
}

fn env_output(name: &str) -> Option<OutputFormat> {
    env::var(name).ok()?.parse().ok()
}

fn env_nonempty(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_format_parse_accepts_plain_text_alias() {
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Plain);
    }
}
