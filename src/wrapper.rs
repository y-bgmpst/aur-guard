use std::{ffi::OsString, process::Command};

use anyhow::{Context, Result};

use crate::{
    aur,
    cli::WrapperArgs,
    config::{Config, OutputFormat},
    llm_optional,
    report::AuditStatus,
    scanner,
};

pub fn run(args: WrapperArgs, config: Config) -> Result<u8> {
    let (command, command_args) = split_command(args.command)?;

    if should_skip_audit(&command_args) {
        return run_command(command, command_args);
    }

    let current_dir = std::env::current_dir().context("failed to read current directory")?;
    let target = aur::prepare_local(&current_dir)?;
    let mut report = scanner::audit_target(&target, &config)?;
    if config.llm.enabled {
        let notes = llm_optional::review(&report, target.root(), &config)?;
        report = report.with_llm_notes(notes);
    }

    match config.output {
        OutputFormat::Json => println!("{}", report.to_json()?),
        OutputFormat::Human => print!("{}", report.to_text(false)),
        OutputFormat::Plain => print!("{}", report.to_text(true)),
    }

    if report.status != AuditStatus::Pass && !config.warn_only {
        return Ok(1);
    }

    run_command(command, command_args)
}

fn split_command(mut raw: Vec<OsString>) -> Result<(OsString, Vec<OsString>)> {
    if raw.is_empty() {
        return Ok((OsString::from("/usr/bin/makepkg"), Vec::new()));
    }

    let first = raw.remove(0);
    if first.to_string_lossy().starts_with('-') {
        raw.insert(0, first);
        Ok((OsString::from("/usr/bin/makepkg"), raw))
    } else {
        match first.to_string_lossy().as_ref() {
            "makepkg" | "/usr/bin/makepkg" => Ok((OsString::from("/usr/bin/makepkg"), raw)),
            other => anyhow::bail!("wrapper only executes /usr/bin/makepkg, not {other}"),
        }
    }
}

fn should_skip_audit(args: &[OsString]) -> bool {
    args.iter().any(|arg| {
        matches!(
            arg.to_string_lossy().as_ref(),
            "--help" | "-h" | "--version" | "-V"
        )
    })
}

fn run_command(command: OsString, args: Vec<OsString>) -> Result<u8> {
    let status = Command::new(&command)
        .args(args)
        .status()
        .with_context(|| format!("failed to run {}", command.to_string_lossy()))?;
    Ok(status.code().unwrap_or(1) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_command_is_makepkg_when_first_arg_is_option() {
        let (cmd, args) = split_command(vec![OsString::from("-si")]).unwrap();
        assert_eq!(cmd, OsString::from("/usr/bin/makepkg"));
        assert_eq!(args, vec![OsString::from("-si")]);
    }

    #[test]
    fn skips_printsrcinfo() {
        assert!(!should_skip_audit(&[OsString::from("--printsrcinfo")]));
    }

    #[test]
    fn only_help_and_version_skip_audit() {
        for arg in [
            "--verifysource",
            "--nobuild",
            "--geninteg",
            "--packagelist",
            "--printsrcinfo",
            "-o",
            "-g",
        ] {
            assert!(!should_skip_audit(&[OsString::from(arg)]), "{arg}");
        }
        for arg in ["--help", "-h", "--version", "-V"] {
            assert!(should_skip_audit(&[OsString::from(arg)]), "{arg}");
        }
    }

    #[test]
    fn rejects_non_makepkg_commands() {
        assert!(split_command(vec![OsString::from("sh")]).is_err());
        assert_eq!(
            split_command(vec![OsString::from("makepkg")]).unwrap().0,
            OsString::from("/usr/bin/makepkg")
        );
    }
}
