# Comparison With mgalgs/aur-sleuth

`aur-sleuth` established the useful workflow: inspect an AUR package before
building it, support local directories, and provide a makepkg wrapper for AUR
helpers.

`aur-guard` keeps that workflow but changes the trust model.

## Kept

- standalone package audit command
- local `--pkgdir` audit
- makepkg/yay/paru style wrapper mode
- OpenAI-compatible provider support, including Claude/Gemini-style models when
  exposed through a compatible endpoint or gateway
- final report intended to guide manual review

## Removed

- mandatory API key
- mandatory LLM analysis
- Python script runtime and `uv`
- rich terminal UI
- HTML/demo assets
- tracker database and broad AUR scanning mode
- automatic `makepkg --printsrcinfo`
- automatic `makepkg --nobuild`

## Redesigned

- deterministic rules run first and work offline
- LLM mode is opt-in and advisory
- package code is never executed for source discovery
- reports use PASS / WARN / FAIL with line references
- default policy is fail closed
- JSON is available for automation
- file reads are bounded and large/vendored directories are skipped by default

## Main Security Difference

The original tool asked an LLM whether it was safe enough to run `makepkg`
operations that may evaluate hostile PKGBUILD content. `aur-guard` avoids that
trust step. It parses and scans static files directly, and marks unresolved dynamic
behavior for manual review.
