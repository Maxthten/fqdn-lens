use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

fn run_cli(data_dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    let database = data_dir.join("cli.db");
    Command::new(env!("CARGO_BIN_EXE_fqdn-lens"))
        .env("LOCALAPPDATA", data_dir)
        .env_remove("FQDN_LENS_CERTSPOTTER_TOKEN")
        .env_remove("FQDN_LENS_URLSCAN_API_KEY")
        .arg("--database")
        .arg(database)
        .args(args)
        .output()
        .expect("run fqdn-lens")
}

#[test]
fn help_contains_bilingual_commands_and_language_override() {
    let temp = tempdir().expect("temp directory");
    let output = run_cli(temp.path(), &["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("管理 registered source 和 credentials"));
    assert!(stdout.contains("Manage registered sources and credentials"));
    assert!(stdout.contains("--language <LANGUAGE>"));
}

#[test]
fn json_source_list_is_parseable_and_keeps_machine_ids() {
    let temp = tempdir().expect("temp directory");
    let output = run_cli(
        temp.path(),
        &["--language", "en-us", "source", "list", "--format", "json"],
    );
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).expect("JSON stdout");
    assert_eq!(value["schema_version"], "fqdn-lens.cli.v1");
    let sources = value["data"].as_array().expect("source array");
    assert_eq!(sources.len(), 4);
    assert!(
        sources
            .iter()
            .any(|item| item["source_id"] == "ct-certspotter")
    );
    assert!(
        sources
            .iter()
            .all(|item| item["credential_state"].is_string())
    );
}

#[test]
fn one_shot_language_override_does_not_persist() {
    let temp = tempdir().expect("temp directory");
    let set = run_cli(
        temp.path(),
        &["config", "set-display-language", "--language", "en-us"],
    );
    assert!(set.status.success());
    let language_override = run_cli(temp.path(), &["--language", "zh-cn", "source", "list"]);
    assert!(language_override.status.success());
    assert!(String::from_utf8_lossy(&language_override.stdout).contains("被动查询"));
    let config = run_cli(temp.path(), &["config", "show", "--format", "json"]);
    let value: Value = serde_json::from_slice(&config.stdout).expect("config JSON");
    assert_eq!(value["data"]["display_language"], "en-us");
}

#[test]
fn userinfo_error_is_json_and_does_not_echo_secret_shaped_input() {
    let temp = tempdir().expect("temp directory");
    let output = run_cli(
        temp.path(),
        &[
            "--language",
            "en-us",
            "collect",
            "--domain",
            "https://user:FAKE_SECRET@example.com/path?token=never",
            "--source",
            "ct-crtsh",
            "--format",
            "json",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&output.stderr).expect("JSON error stderr");
    assert_eq!(value["error"]["code"], "url_userinfo_denied");
    let rendered = String::from_utf8_lossy(&output.stderr);
    assert!(!rendered.contains("FAKE_SECRET"));
    assert!(!rendered.contains("token=never"));
}

#[test]
fn missing_credential_collection_reports_zero_requests_and_localized_message() {
    let temp = tempdir().expect("temp directory");
    let output = run_cli(
        temp.path(),
        &[
            "--language",
            "zh-cn",
            "collect",
            "--domain",
            "example.com",
            "--source",
            "ct-certspotter",
            "--format",
            "json",
        ],
    );
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("JSON collection output");
    assert_eq!(value["data"]["statuses"]["ct-certspotter"]["requests"], 0);
    assert_eq!(value["messages"][0]["code"], "credential_missing");
    assert!(
        value["messages"][0]["message"]
            .as_str()
            .unwrap()
            .contains("尚未配置")
    );
}
