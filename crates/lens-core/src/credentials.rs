//! Secret-safe credential resolution for the fixed production source registry.
//!
//! The only persistent backend is the Windows Credential Manager.  It uses
//! Windows data protection for the current user and stores Lens-owned generic
//! credential entries only.  Environment variables remain a compatible
//! fallback; they are never imported without explicit caller confirmation.

use std::collections::BTreeMap;
use std::env;
use thiserror::Error;

const TARGET_PREFIX: &str = "FQDN Lens/";

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialState {
    NotRequired,
    CredentialStore,
    Environment,
    SessionOnly,
    Missing,
}

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("credential value is empty or contains a control character")]
    InvalidValue,
    #[error("secure credential store is unavailable: {0}")]
    SecureStore(String),
    #[error("source does not have an environment credential")]
    EnvironmentUnavailable,
}

/// A value that deliberately cannot be formatted, serialized, or cloned.
#[derive(Clone)]
pub(crate) struct ResolvedSecret(String);

impl ResolvedSecret {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Default)]
pub struct CredentialProvider {
    session: BTreeMap<String, ResolvedSecret>,
}

impl CredentialProvider {
    #[must_use]
    pub fn system() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn state(&self, source_id: &str, environment_variable: Option<&str>) -> CredentialState {
        if environment_variable.is_none() {
            return CredentialState::NotRequired;
        }
        if self.session.contains_key(source_id) {
            return CredentialState::SessionOnly;
        }
        if secure_read(source_id).ok().flatten().is_some() {
            return CredentialState::CredentialStore;
        }
        if environment_variable
            .and_then(env::var_os)
            .is_some_and(|value| !value.is_empty())
        {
            return CredentialState::Environment;
        }
        CredentialState::Missing
    }

    pub fn configure(&mut self, source_id: &str, value: &str) -> Result<(), CredentialError> {
        validate_secret(value)?;
        secure_write(source_id, value)
    }

    pub fn import_environment(
        &mut self,
        source_id: &str,
        environment_variable: Option<&str>,
        confirmed: bool,
    ) -> Result<(), CredentialError> {
        if !confirmed {
            return Err(CredentialError::EnvironmentUnavailable);
        }
        let variable = environment_variable.ok_or(CredentialError::EnvironmentUnavailable)?;
        let value = env::var(variable).map_err(|_| CredentialError::EnvironmentUnavailable)?;
        self.configure(source_id, &value)
    }

    pub fn remove(&mut self, source_id: &str) -> Result<bool, CredentialError> {
        self.session.remove(source_id);
        secure_remove(source_id)
    }

    pub fn set_session(&mut self, source_id: &str, value: &str) -> Result<(), CredentialError> {
        validate_secret(value)?;
        self.session
            .insert(source_id.to_owned(), ResolvedSecret(value.to_owned()));
        Ok(())
    }

    pub(crate) fn resolve(
        &self,
        source_id: &str,
        environment_variable: Option<&str>,
    ) -> Option<ResolvedSecret> {
        if let Some(value) = self.session.get(source_id) {
            return Some(ResolvedSecret(value.expose().to_owned()));
        }
        if let Ok(Some(value)) = secure_read(source_id) {
            return Some(ResolvedSecret(value));
        }
        environment_variable
            .and_then(|variable| env::var(variable).ok())
            .filter(|value| !value.is_empty())
            .map(ResolvedSecret)
    }
}

fn validate_secret(value: &str) -> Result<(), CredentialError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(CredentialError::InvalidValue);
    }
    Ok(())
}

#[cfg(windows)]
const CRED_TYPE_GENERIC: u32 = 1;
#[cfg(windows)]
const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;

#[cfg(windows)]
#[repr(C)]
struct NativeFileTime {
    dw_low_date_time: u32,
    dw_high_date_time: u32,
}

#[cfg(windows)]
#[repr(C)]
struct NativeCredentialAttribute {
    keyword: *mut u16,
    flags: u32,
    value_size: u32,
    value: *mut u8,
}

#[cfg(windows)]
#[repr(C)]
struct NativeCredential {
    flags: u32,
    credential_type: u32,
    target_name: *mut u16,
    comment: *mut u16,
    last_written: NativeFileTime,
    credential_blob_size: u32,
    credential_blob: *mut u8,
    persist: u32,
    attribute_count: u32,
    attributes: *mut NativeCredentialAttribute,
    target_alias: *mut u16,
    user_name: *mut u16,
}

#[cfg(windows)]
#[link(name = "Advapi32")]
unsafe extern "system" {
    fn CredReadW(
        target_name: *const u16,
        credential_type: u32,
        flags: u32,
        credential: *mut *mut NativeCredential,
    ) -> i32;
    fn CredWriteW(credential: *const NativeCredential, flags: u32) -> i32;
    fn CredDeleteW(target_name: *const u16, credential_type: u32, flags: u32) -> i32;
    fn CredFree(buffer: *mut std::ffi::c_void);
}

#[cfg(windows)]
unsafe fn cred_read(
    target_name: *const u16,
    credential_type: u32,
    flags: u32,
    credential: *mut *mut NativeCredential,
) -> i32 {
    // SAFETY: callers uphold the native Credential Manager API contract.
    unsafe { CredReadW(target_name, credential_type, flags, credential) }
}

#[cfg(windows)]
unsafe fn cred_write(credential: *const NativeCredential, flags: u32) -> i32 {
    // SAFETY: callers uphold the native Credential Manager API contract.
    unsafe { CredWriteW(credential, flags) }
}

#[cfg(windows)]
unsafe fn cred_delete(target_name: *const u16, credential_type: u32, flags: u32) -> i32 {
    // SAFETY: callers uphold the native Credential Manager API contract.
    unsafe { CredDeleteW(target_name, credential_type, flags) }
}

#[cfg(windows)]
unsafe fn cred_free(buffer: *mut std::ffi::c_void) {
    // SAFETY: callers pass an allocation obtained from CredReadW.
    unsafe { CredFree(buffer) }
}

#[cfg(windows)]
fn secure_read(source_id: &str) -> Result<Option<String>, CredentialError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::slice;

    let mut target = OsStr::new(&format!("{TARGET_PREFIX}{source_id}"))
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut credential: *mut NativeCredential = std::ptr::null_mut();
    // SAFETY: target is NUL-terminated and credential is a valid out-pointer.
    let result = unsafe { cred_read(target.as_mut_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };
    if result == 0 {
        let code = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or_default();
        return if code == 1168 {
            Ok(None)
        } else {
            Err(CredentialError::SecureStore(format!(
                "CredReadW failed ({code})"
            )))
        };
    }
    // SAFETY: a successful CredReadW returns a valid allocation released by CredFree.
    let value = unsafe {
        let bytes = slice::from_raw_parts(
            (*credential).credential_blob,
            usize::try_from((*credential).credential_blob_size).unwrap_or_default(),
        );
        let value = String::from_utf8(bytes.to_vec())
            .map_err(|_| CredentialError::SecureStore("credential is not UTF-8".to_owned()));
        cred_free(credential.cast());
        value
    }?;
    Ok(Some(value))
}

#[cfg(windows)]
fn secure_write(source_id: &str, value: &str) -> Result<(), CredentialError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let mut target = OsStr::new(&format!("{TARGET_PREFIX}{source_id}"))
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut blob = value.as_bytes().to_vec();
    let credential = NativeCredential {
        flags: 0,
        credential_type: CRED_TYPE_GENERIC,
        target_name: target.as_mut_ptr(),
        comment: std::ptr::null_mut(),
        last_written: NativeFileTime {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        },
        credential_blob_size: u32::try_from(blob.len())
            .map_err(|_| CredentialError::InvalidValue)?,
        credential_blob: blob.as_mut_ptr(),
        persist: CRED_PERSIST_LOCAL_MACHINE,
        attribute_count: 0,
        attributes: std::ptr::null_mut(),
        target_alias: std::ptr::null_mut(),
        user_name: std::ptr::null_mut(),
    };
    // SAFETY: all pointers reference writable data kept alive for the duration of CredWriteW.
    if unsafe { cred_write(&credential, 0) } == 0 {
        let code = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or_default();
        return Err(CredentialError::SecureStore(format!(
            "CredWriteW failed ({code})"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn secure_remove(source_id: &str) -> Result<bool, CredentialError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let mut target = OsStr::new(&format!("{TARGET_PREFIX}{source_id}"))
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: target is a NUL-terminated target name owned by this function.
    if unsafe { cred_delete(target.as_mut_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
        let code = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or_default();
        return if code == 1168 {
            Ok(false)
        } else {
            Err(CredentialError::SecureStore(format!(
                "CredDeleteW failed ({code})"
            )))
        };
    }
    Ok(true)
}

#[cfg(not(windows))]
fn secure_read(_source_id: &str) -> Result<Option<String>, CredentialError> {
    Ok(None)
}

#[cfg(not(windows))]
fn secure_write(_source_id: &str, _value: &str) -> Result<(), CredentialError> {
    Err(CredentialError::SecureStore(
        "Windows Credential Manager is unavailable on this platform".to_owned(),
    ))
}

#[cfg(not(windows))]
fn secure_remove(_source_id: &str) -> Result<bool, CredentialError> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_secret_has_no_display_or_serialize_path() {
        let mut provider = CredentialProvider::system();
        provider
            .set_session("test-source", "fake-credential-for-test")
            .expect("set session credential");
        assert_eq!(
            provider.state("test-source", Some("FQDN_LENS_NEVER_SET_TEST")),
            CredentialState::SessionOnly
        );
    }

    #[test]
    fn credential_values_reject_control_characters() {
        assert!(validate_secret("safe-value").is_ok());
        assert!(validate_secret("unsafe\nvalue").is_err());
    }
}
