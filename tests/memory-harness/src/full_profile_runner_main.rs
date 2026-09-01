use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use edge_memory_harness::full_profile_readiness::evaluate_full_profile;
use edge_memory_harness::full_profile_runner::{
    build_verified_input, validate_runner_entrypoints, validate_runner_registry,
    FullProfileRunnerEvent, RunnerJobOutcome, RunnerLifecycle, FULL_PROFILE_JOBS,
};
use edge_memory_harness::report_io::{publish_canonical_bytes, publish_digest, sha256_hex};
use edge_memory_harness::HarnessError;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("full profile runner error: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), HarnessError> {
    let (command, options) = parse(arguments)?;
    match command.as_str() {
        "plan" => {
            exact_keys(&options, &[])?;
            validate_runner_registry()?;
            validate_runner_entrypoints(Path::new("."))?;
            for job in FULL_PROFILE_JOBS {
                println!(
                    "job={} script={} output={} report={} scenarios={}",
                    job.job_id,
                    job.script_path,
                    job.output_directory,
                    job.report_path,
                    job.scenarios.join(",")
                );
            }
        }
        "run" => run_profile(&options)?,
        _ => return Err(HarnessError::new("unknown full profile runner command")),
    }
    Ok(())
}

fn run_profile(options: &BTreeMap<String, String>) -> Result<(), HarnessError> {
    exact_keys(
        options,
        &[
            "--output-root",
            "--build-identity",
            "--platform",
            "--architecture",
        ],
    )?;
    validate_runner_registry()?;
    let mut lifecycle = RunnerLifecycle::new();
    lifecycle.transition(FullProfileRunnerEvent::PlanValidated)?;
    let output_root = PathBuf::from(required(options, "--output-root")?);
    reject_existing(&output_root)?;
    fs::create_dir(&output_root)
        .map_err(|_| HarnessError::new("full profile output root cannot be created"))?;
    let build_identity = required(options, "--build-identity")?;
    let platform = required(options, "--platform")?;
    let architecture = required(options, "--architecture")?;
    let mut outcomes = Vec::with_capacity(FULL_PROFILE_JOBS.len());

    for job in FULL_PROFILE_JOBS {
        lifecycle.transition(FullProfileRunnerEvent::JobStarted)?;
        let script = physical_regular(Path::new(job.script_path))?;
        let job_output = output_root.join(job.output_directory);
        println!("full profile job started job={}", job.job_id);
        let status = Command::new(script)
            .arg(&job_output)
            .status()
            .map_err(|_| HarnessError::new("full profile job could not start"))?;
        if !status.success() {
            lifecycle.transition(FullProfileRunnerEvent::Failed)?;
            return Err(HarnessError::new("full profile job failed"));
        }
        let report_path = job_output.join(job.report_path);
        let digest_path = job_output.join(job.digest_path);
        physical_regular(&report_path)?;
        physical_regular(&digest_path)?;
        let report = fs::read(&report_path)
            .map_err(|_| HarnessError::new("full profile job report cannot be read"))?;
        let digest_bytes = fs::read(&digest_path)
            .map_err(|_| HarnessError::new("full profile job digest cannot be read"))?;
        let digest = parse_digest(&digest_bytes)?;
        if sha256_hex(&report) != digest {
            return Err(HarnessError::new("full profile job digest mismatch"));
        }
        if extract_build_identity(&report)? != build_identity {
            return Err(HarnessError::new(
                "full profile job source identity mismatch",
            ));
        }
        println!(
            "full profile job verified job={} digest={}",
            job.job_id, digest
        );
        outcomes.push(RunnerJobOutcome {
            job_id: job.job_id.to_string(),
            build_identity: build_identity.to_string(),
            report_sha256: digest,
            script_passed: true,
        });
        lifecycle.transition(FullProfileRunnerEvent::JobVerified)?;
    }

    let input = build_verified_input(build_identity, platform, architecture, outcomes)?;
    lifecycle.transition(FullProfileRunnerEvent::InventoryBuilt)?;
    let mut inventory = serde_json::to_string_pretty(&input)
        .map_err(|_| HarnessError::new("full profile inventory encoding failed"))?;
    inventory.push('\n');
    let inventory_publish =
        publish_canonical_bytes(&output_root.join("inventory-v1.json"), inventory.as_bytes())?;
    publish_digest(
        &output_root.join("inventory-v1.sha256"),
        &inventory_publish.sha256,
    )?;
    lifecycle.transition(FullProfileRunnerEvent::Published)?;

    let readiness = evaluate_full_profile(input)?;
    if !readiness.ready {
        return Err(HarnessError::new(
            "full profile runner produced incomplete readiness",
        ));
    }
    let readiness_json = readiness.to_canonical_json()?;
    let readiness_publish = publish_canonical_bytes(
        &output_root.join("readiness-v1.json"),
        readiness_json.as_bytes(),
    )?;
    publish_digest(
        &output_root.join("readiness-v1.sha256"),
        &readiness_publish.sha256,
    )?;
    println!(
        "full profile runner completed jobs={} scenarios={} readiness_digest={}",
        FULL_PROFILE_JOBS.len(),
        readiness.scenarios.len(),
        readiness_publish.sha256
    );
    Ok(())
}

fn extract_build_identity(report: &[u8]) -> Result<String, HarnessError> {
    let value: serde_json::Value = serde_json::from_slice(report)
        .map_err(|_| HarnessError::new("full profile job report is not JSON"))?;
    value
        .get("build_identity")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .get("identity")
                .and_then(|identity| identity.get("build_identity"))
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_string)
        .ok_or_else(|| HarnessError::new("full profile job report build identity is missing"))
}

fn physical_regular(path: &Path) -> Result<&Path, HarnessError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HarnessError::new("full profile physical file is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HarnessError::new(
            "full profile file must be physical and regular",
        ));
    }
    Ok(path)
}

fn reject_existing(path: &Path) -> Result<(), HarnessError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(HarnessError::new("full profile output root must be new")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(HarnessError::new(
            "full profile output root cannot be inspected",
        )),
    }
}

fn parse(arguments: Vec<String>) -> Result<(String, BTreeMap<String, String>), HarnessError> {
    let mut values = arguments.into_iter();
    let command = values
        .next()
        .ok_or_else(|| HarnessError::new("full profile runner command is required"))?;
    let mut options = BTreeMap::new();
    while let Some(key) = values.next() {
        if !key.starts_with("--") || options.contains_key(&key) {
            return Err(HarnessError::new("full profile runner option is invalid"));
        }
        let value = values
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| HarnessError::new("full profile runner option value is missing"))?;
        options.insert(key, value);
    }
    Ok((command, options))
}

fn exact_keys(options: &BTreeMap<String, String>, expected: &[&str]) -> Result<(), HarnessError> {
    if options.len() != expected.len() || expected.iter().any(|key| !options.contains_key(*key)) {
        return Err(HarnessError::new(
            "full profile runner option set is invalid",
        ));
    }
    Ok(())
}

fn required<'a>(options: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, HarnessError> {
    options
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| HarnessError::new("full profile runner option is missing"))
}

fn parse_digest(bytes: &[u8]) -> Result<String, HarnessError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HarnessError::new("full profile runner digest is not UTF-8"))?;
    let digest = text
        .strip_suffix('\n')
        .filter(|value| {
            value.len() == 64
                && !value.contains('\n')
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| HarnessError::new("full profile runner digest is not canonical"))?;
    Ok(digest.to_string())
}
