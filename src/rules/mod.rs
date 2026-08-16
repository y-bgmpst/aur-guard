use std::sync::OnceLock;

use regex::Regex;

mod line_rules;
mod pkgbuild;
mod text;

pub use pkgbuild::scan_pkgbuild_metadata;
pub use pkgbuild::scan_srcinfo;
pub use text::scan_text_file;

fn first_lines(text: &str, max: usize) -> String {
    text.lines().take(max).collect::<Vec<_>>().join("\n")
}

fn re(pattern: &'static str) -> &'static Regex {
    type RegexCache = std::sync::Mutex<std::collections::HashMap<&'static str, &'static Regex>>;
    static CACHE: OnceLock<RegexCache> = OnceLock::new();

    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut guard = cache.lock().expect("regex cache poisoned");
    if let Some(regex) = guard.get(pattern) {
        return regex;
    }
    let regex = Box::leak(Box::new(Regex::new(pattern).expect("valid regex")));
    guard.insert(pattern, regex);
    regex
}
