use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeVerdict {
    Accepted,
    Root,
    Wildcard,
    OutOfScope,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DomainCandidate {
    pub value: Option<String>,
    pub verdict: ScopeVerdict,
    pub notes: Vec<String>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DomainError {
    #[error("domain is empty")]
    Empty,
    #[error("domain contains a control character")]
    ControlCharacter,
    #[error("domain has an invalid label")]
    InvalidLabel,
    #[error("domain is too long")]
    TooLong,
    #[error("domain is not a valid root domain")]
    InvalidRoot,
}

/// Normalizes a user-supplied root domain conservatively. Unicode labels are
/// accepted only when `url` can serialize them to an ASCII host; malformed
/// labels remain errors instead of receiving lossy repairs.
pub fn normalize_root_domain(input: &str) -> Result<String, DomainError> {
    let candidate = normalize_host(input)?;
    if candidate.starts_with("*.") || !candidate.contains('.') {
        return Err(DomainError::InvalidRoot);
    }
    Ok(candidate)
}

/// Extracts a URL host when the input is URL-shaped, otherwise normalizes it
/// as a host. Path, port, and user information never enter the resulting FQDN.
pub fn normalize_candidate(input: &str, root: &str, include_root: bool) -> DomainCandidate {
    let mut notes = Vec::new();
    if input.chars().any(char::is_control) {
        return invalid("control character");
    }
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return invalid("empty input");
    }

    let (host_input, was_url) = match Url::parse(trimmed) {
        Ok(url) if url.has_authority() => match url.host_str() {
            Some(host) => (host.to_owned(), true),
            None => return invalid("URL does not contain a host"),
        },
        _ => (trimmed.to_owned(), false),
    };
    if was_url {
        notes.push("url_host_extracted".to_owned());
    }

    let wildcard = host_input.trim_start().starts_with("*.");
    let host_without_wildcard = host_input.trim_start_matches("*.");
    let normalized = match normalize_host(host_without_wildcard) {
        Ok(value) => value,
        Err(error) => return invalid(error.to_string()),
    };
    if wildcard {
        notes.push("wildcard_certificate_name".to_owned());
        return DomainCandidate {
            value: Some(normalized),
            verdict: ScopeVerdict::Wildcard,
            notes,
        };
    }
    if normalized == root {
        notes.push("root_domain".to_owned());
        return DomainCandidate {
            value: Some(normalized),
            verdict: if include_root {
                ScopeVerdict::Accepted
            } else {
                ScopeVerdict::Root
            },
            notes,
        };
    }
    if !normalized.ends_with(root)
        || normalized
            .strip_suffix(root)
            .is_none_or(|prefix| !prefix.ends_with('.'))
    {
        return DomainCandidate {
            value: Some(normalized),
            verdict: ScopeVerdict::OutOfScope,
            notes: vec!["suffix_boundary_mismatch".to_owned()],
        };
    }

    DomainCandidate {
        value: Some(normalized),
        verdict: ScopeVerdict::Accepted,
        notes,
    }
}

fn invalid(note: impl Into<String>) -> DomainCandidate {
    DomainCandidate {
        value: None,
        verdict: ScopeVerdict::Invalid,
        notes: vec![note.into()],
    }
}

fn normalize_host(input: &str) -> Result<String, DomainError> {
    if input.chars().any(char::is_control) {
        return Err(DomainError::ControlCharacter);
    }
    let value = input.trim().trim_end_matches('.');
    if value.is_empty() {
        return Err(DomainError::Empty);
    }
    // `url` supplies UTS-46 / Punycode serialization. Prefixing a scheme
    // avoids accepting paths and ports here; callers extract URL hosts first.
    let parsed = Url::parse(&format!("http://{value}")).map_err(|_| DomainError::InvalidLabel)?;
    if parsed.path() != "/" || parsed.port().is_some() || parsed.username() != "" {
        return Err(DomainError::InvalidLabel);
    }
    let host = parsed
        .host_str()
        .ok_or(DomainError::InvalidLabel)?
        .to_ascii_lowercase();
    if host.len() > 253 {
        return Err(DomainError::TooLong);
    }
    if host.parse::<std::net::IpAddr>().is_ok()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
    {
        return Err(DomainError::InvalidLabel);
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_trailing_dot_and_scope() {
        let candidate = normalize_candidate("API.Acme.Test.", "acme.test", false);
        assert_eq!(candidate.value.as_deref(), Some("api.acme.test"));
        assert_eq!(candidate.verdict, ScopeVerdict::Accepted);
    }

    #[test]
    fn extracts_only_url_host() {
        let candidate = normalize_candidate(
            "https://user:secret@api.acme.test:8443/a/path?q=1",
            "acme.test",
            false,
        );
        assert_eq!(candidate.value.as_deref(), Some("api.acme.test"));
        assert_eq!(candidate.verdict, ScopeVerdict::Accepted);
        assert_eq!(candidate.notes, ["url_host_extracted"]);
    }

    #[test]
    fn rejects_suffix_lookalikes() {
        for value in ["evil-acme.test", "acme.test.evil.invalid"] {
            assert_eq!(
                normalize_candidate(value, "acme.test", false).verdict,
                ScopeVerdict::OutOfScope
            );
        }
    }

    #[test]
    fn classifies_wildcard_and_root() {
        assert_eq!(
            normalize_candidate("*.acme.test", "acme.test", false).verdict,
            ScopeVerdict::Wildcard
        );
        assert_eq!(
            normalize_candidate("acme.test", "acme.test", false).verdict,
            ScopeVerdict::Root
        );
    }

    #[test]
    fn normalizes_unicode_conservatively() {
        let root = normalize_root_domain("bücher.example").expect("valid IDN");
        assert_eq!(root, "xn--bcher-kva.example");
    }

    #[test]
    fn rejects_malformed_values() {
        for value in ["", "a..acme.test", "-a.acme.test", "a.acme.test\n"] {
            assert_eq!(
                normalize_candidate(value, "acme.test", false).verdict,
                ScopeVerdict::Invalid
            );
        }
    }
}
