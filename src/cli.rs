use std::{ffi::OsString, path::PathBuf, process::ExitCode};

use anyhow::{Context, Result, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, error::ErrorKind};

use crate::{
    aur,
    config::{Config, OutputFormat},
    llm_optional, scanner, wrapper,
};

#[derive(Debug, Parser)]
#[command(name = "aur-guard")]
#[command(about = "Static AUR package security auditing CLI")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Audit an AUR package name or a local directory containing PKGBUILD.
    Audit(AuditArgs),
    /// Audit the current directory and then run makepkg-compatible command args.
    Wrapper(WrapperArgs),
}

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// AUR package name to clone and audit.
    pub package: Option<String>,

    /// Audit an existing local package directory containing a PKGBUILD.
    #[arg(long, value_name = "DIR")]
    pub pkgdir: Option<PathBuf>,

    /// Override AUR clone URL. Defaults to https://aur.archlinux.org/<package>.git.
    #[arg(long)]
    pub clone_url: Option<String>,

    /// Emit JSON output.
    #[arg(long)]
    pub json: bool,

    /// Emit plain text output.
    #[arg(long)]
    pub plain: bool,

    /// Enable optional OpenAI-compatible LLM review.
    ///
    /// Claude, Gemini, and other models require an OpenAI-compatible endpoint.
    #[arg(long)]
    pub llm: bool,

    /// Disable optional LLM review even if config enables it.
    #[arg(long)]
    pub no_llm: bool,

    /// Exit zero even when warnings or failures are reported.
    #[arg(long)]
    pub warn_only: bool,

    /// Preserve temporary clone directory after auditing.
    #[arg(long)]
    pub keep_tmp: bool,

    /// Include normally ignored vendored/build directories.
    #[arg(long)]
    pub include_vendored: bool,

    /// Fetch small remote source files over HTTPS for static inspection.
    #[arg(long)]
    pub fetch_remote_sources: bool,

    /// Maximum file size to inspect, in bytes.
    #[arg(long)]
    pub max_file_bytes: Option<u64>,

    /// Maximum number of files to inspect.
    #[arg(long)]
    pub max_files: Option<usize>,

    /// Approximate prompt token budget for optional LLM review.
    #[arg(long)]
    pub llm_token_budget: Option<usize>,
}

#[derive(Debug, Args)]
pub struct WrapperArgs {
    /// Exit zero after reporting warnings or failures, then continue to makepkg.
    #[arg(long)]
    pub warn_only: bool,

    /// Extra arguments or command to run after audit.
    #[arg(last = true, allow_hyphen_values = true, trailing_var_arg = true)]
    pub command: Vec<OsString>,
}

pub fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let kind = err.kind();
            let _ = err.print();
            let code = match kind {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
                _ => 3,
            };
            return ExitCode::from(code);
        }
    };

    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("aur-guard: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    match cli.command {
        Commands::Audit(args) => run_audit(args),
        Commands::Wrapper(args) => {
            let mut config = Config::load()?;
            if args.warn_only {
                config.warn_only = true;
            }
            wrapper::run(args, config)
        }
    }
}

pub fn run_audit(args: AuditArgs) -> Result<u8> {
    let mut config = Config::load()?;
    apply_audit_overrides(&mut config, &args)?;

    if args.package.is_some() && args.pkgdir.is_some() {
        bail!("provide either a package name or --pkgdir, not both");
    }
    if args.package.is_none() && args.pkgdir.is_none() {
        Cli::command().print_help()?;
        eprintln!();
        return Ok(3);
    }

    let target = if let Some(pkgdir) = &args.pkgdir {
        aur::prepare_local(pkgdir)
            .with_context(|| format!("invalid --pkgdir {}", pkgdir.display()))?
    } else {
        let package = args.package.as_deref().expect("checked above");
        aur::clone_package(package, args.clone_url.as_deref(), &config)?
    };

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

    if target.is_temp() && config.keep_tmp {
        eprintln!(
            "temporary audit directory kept at {}",
            target.root().display()
        );
        target.keep();
    }

    Ok(exit_for_report(report.status, config.warn_only))
}

pub fn exit_for_report(status: crate::report::AuditStatus, warn_only: bool) -> u8 {
    if warn_only || status == crate::report::AuditStatus::Pass {
        0
    } else {
        1
    }
}

fn apply_audit_overrides(config: &mut Config, args: &AuditArgs) -> Result<()> {
    if args.json && args.plain {
        bail!("--json and --plain are mutually exclusive");
    }
    if args.json {
        config.output = OutputFormat::Json;
    }
    if args.plain {
        config.output = OutputFormat::Plain;
    }
    if args.llm && args.no_llm {
        bail!("--llm and --no-llm are mutually exclusive");
    }
    if args.llm {
        config.llm.enabled = true;
    }
    if args.no_llm {
        config.llm.enabled = false;
    }
    if args.warn_only {
        config.warn_only = true;
    }
    if args.keep_tmp {
        config.keep_tmp = true;
    }
    if args.include_vendored {
        config.include_vendored = true;
    }
    if args.fetch_remote_sources {
        config.fetch_remote_sources = true;
    }
    if let Some(value) = args.max_file_bytes {
        config.max_file_bytes = value;
    }
    if let Some(value) = args.max_files {
        config.max_files = value;
    }
    if let Some(value) = args.llm_token_budget {
        config.llm.token_budget = value;
    }
    Ok(())
}
