//! In-process libcoraza loader (issue #86 remainder).
//!
//! Wardnet does not reimplement OWASP CRS. When `CORAZA_LIB_PATH` is set, the
//! process `dlopen`s operator-supplied libcoraza and evaluates each live
//! `/gateway` transaction through the C ABI. CI uses a fixture cdylib that
//! exports the same symbols; production points at a real libcoraza + CRS file.

use std::ffi::{CStr, CString};
use std::net::IpAddr;
use std::os::raw::{c_char, c_int};
use std::path::Path;
use std::ptr;

use libloading::Library;

use crate::coraza_audit::CorazaIngestedHit;
use crate::proven_engine::ProvenEngineOutcome;

const CORAZA_ERROR: c_int = -1;
const CORAZA_INTERRUPTION: c_int = 1;

#[repr(C)]
struct CorazaIntervention {
    action: *mut c_char,
    status: c_int,
    pause: c_int,
    disruptive: c_int,
    data: *mut c_char,
    rule_id: c_int,
}

struct Api {
    new_waf_config: unsafe extern "C" fn() -> usize,
    rules_add: unsafe extern "C" fn(usize, *const c_char) -> c_int,
    rules_add_file: unsafe extern "C" fn(usize, *const c_char) -> c_int,
    free_waf_config: unsafe extern "C" fn(usize) -> c_int,
    new_waf: unsafe extern "C" fn(usize, *mut *mut c_char) -> usize,
    new_transaction: unsafe extern "C" fn(usize) -> usize,
    process_connection:
        unsafe extern "C" fn(usize, *const c_char, c_int, *const c_char, c_int) -> c_int,
    process_uri: unsafe extern "C" fn(usize, *const c_char, *const c_char, *const c_char) -> c_int,
    add_request_header:
        unsafe extern "C" fn(usize, *const c_char, c_int, *const c_char, c_int) -> c_int,
    process_request_headers: unsafe extern "C" fn(usize) -> c_int,
    append_request_body: unsafe extern "C" fn(usize, *const u8, c_int) -> c_int,
    process_request_body: unsafe extern "C" fn(usize) -> c_int,
    intervention: unsafe extern "C" fn(usize) -> *mut CorazaIntervention,
    free_intervention: unsafe extern "C" fn(*mut CorazaIntervention) -> c_int,
    free_transaction: unsafe extern "C" fn(usize) -> c_int,
    free_waf: unsafe extern "C" fn(usize) -> c_int,
    rules_count: unsafe extern "C" fn(usize) -> c_int,
    free_string: unsafe extern "C" fn(*mut c_char),
    process_logging: unsafe extern "C" fn(usize) -> c_int,
}

/// Loaded libcoraza instance. The library handle outlives every function
/// pointer copied out of it.
pub struct InProcessCoraza {
    api: Api,
    waf: usize,
    rules: i32,
    _lib: Library,
}

impl std::fmt::Debug for InProcessCoraza {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessCoraza")
            .field("rules", &self.rules)
            .finish()
    }
}

impl InProcessCoraza {
    /// `dlopen` `lib_path` and construct a WAF from a CRS file and/or extra
    /// SecLang directives. Empty rulesets are rejected so a missing CRS cannot
    /// silently become allow.
    pub fn load(
        lib_path: &Path,
        rules_path: Option<&Path>,
        directives: Option<&str>,
    ) -> Result<Self, String> {
        if !lib_path.exists() {
            return Err(format!(
                "CORAZA_LIB_PATH {} does not exist",
                lib_path.display()
            ));
        }
        if rules_path.is_none() && directives.is_none_or(|text| text.trim().is_empty()) {
            return Err(
                "CORAZA_LIB_PATH requires CORAZA_RULES_PATH or CORAZA_DIRECTIVES".to_string(),
            );
        }
        if let Some(path) = rules_path
            && !path.is_file()
        {
            return Err(format!(
                "CORAZA_RULES_PATH {} is not a file",
                path.display()
            ));
        }

        // SAFETY: operator-supplied path; we only call documented libcoraza
        // exports after looking up symbols by name.
        let lib = unsafe { Library::new(lib_path) }.map_err(|error| {
            format!(
                "failed to load libcoraza from {}: {error}",
                lib_path.display()
            )
        })?;
        let api = load_api(&lib)?;

        // SAFETY: symbols came from this library; config/waf handles are
        // opaque libcoraza values used only with those symbols.
        let loaded = unsafe { construct_waf(&api, rules_path, directives)? };
        Ok(Self {
            api,
            waf: loaded.waf,
            rules: loaded.rules,
            _lib: lib,
        })
    }

    /// Number of directive sources loaded into this WAF (file and/or string).
    pub fn rules(&self) -> i32 {
        self.rules
    }

    /// Evaluate one HTTP transaction. Never includes the library path in the
    /// outcome reason (that can identify a host layout).
    pub fn evaluate(
        &self,
        method: &str,
        uri: &str,
        body: &str,
        client_ip: Option<IpAddr>,
    ) -> ProvenEngineOutcome {
        match self.evaluate_inner(method, uri, body, client_ip) {
            Ok(outcome) => outcome,
            Err(reason) => ProvenEngineOutcome::Unavailable { reason },
        }
    }

    fn evaluate_inner(
        &self,
        method: &str,
        uri: &str,
        body: &str,
        client_ip: Option<IpAddr>,
    ) -> Result<ProvenEngineOutcome, String> {
        let method_c = c_string(method)?;
        let uri_c = c_string(uri)?;
        let proto = c_string("HTTP/1.1")?;
        let source = c_string(
            &client_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string()),
        )?;
        let server = c_string("")?;

        // SAFETY: `self.waf` was created by `coraza_new_waf` on this library
        // and is freed only in Drop. Transaction handles stay local.
        unsafe {
            let tx = (self.api.new_transaction)(self.waf);
            if tx == 0 {
                return Err("coraza in-process failed to open a transaction".to_string());
            }
            let tx = TxGuard { api: &self.api, tx };
            if (self.api.process_connection)(tx.tx, source.as_ptr(), 0, server.as_ptr(), 80)
                == CORAZA_ERROR
            {
                return Err("coraza in-process connection phase failed".to_string());
            }
            if (self.api.process_uri)(tx.tx, uri_c.as_ptr(), method_c.as_ptr(), proto.as_ptr())
                == CORAZA_ERROR
            {
                return Err("coraza in-process uri phase failed".to_string());
            }
            let host_name = c_string("Host")?;
            let host_value = c_string("wardnet")?;
            let _ = (self.api.add_request_header)(
                tx.tx,
                host_name.as_ptr(),
                c_len("Host".len())?,
                host_value.as_ptr(),
                c_len("wardnet".len())?,
            );
            let header_rc = (self.api.process_request_headers)(tx.tx);
            if header_rc == CORAZA_ERROR {
                return Err("coraza in-process header phase failed".to_string());
            }
            if header_rc == CORAZA_INTERRUPTION {
                return Ok(hit_from_intervention(&self.api, tx.tx, uri, client_ip));
            }
            if !body.is_empty() {
                let rc = (self.api.append_request_body)(tx.tx, body.as_ptr(), c_len(body.len())?);
                if rc == CORAZA_ERROR {
                    return Err("coraza in-process body write failed".to_string());
                }
            }
            let body_rc = (self.api.process_request_body)(tx.tx);
            if body_rc == CORAZA_ERROR {
                return Err("coraza in-process body phase failed".to_string());
            }
            if body_rc == CORAZA_INTERRUPTION {
                return Ok(hit_from_intervention(&self.api, tx.tx, uri, client_ip));
            }
            Ok(ProvenEngineOutcome::Clean)
        }
    }
}

impl Drop for InProcessCoraza {
    fn drop(&mut self) {
        // SAFETY: `self.waf` is a live libcoraza WAF handle owned by this
        // value; the library is still loaded (`_lib` drops after this Drop).
        unsafe {
            (self.api.free_waf)(self.waf);
        }
    }
}

// libcoraza WAF instances are documented as concurrent-safe; function pointers
// copied from the loaded module are immutable. The test stub serializes its
// handle maps with a mutex.
unsafe impl Send for InProcessCoraza {}
unsafe impl Sync for InProcessCoraza {}

struct LoadedWaf {
    waf: usize,
    rules: i32,
}

struct TxGuard<'a> {
    api: &'a Api,
    tx: usize,
}

impl Drop for TxGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            (self.api.process_logging)(self.tx);
            (self.api.free_transaction)(self.tx);
        }
    }
}

fn load_api(lib: &Library) -> Result<Api, String> {
    // SAFETY: each lookup is a named libcoraza export; the `Library` outlives
    // the copied function pointers because `_lib` is stored on the engine.
    unsafe {
        Ok(Api {
            new_waf_config: symbol(lib, b"coraza_new_waf_config\0")?,
            rules_add: symbol(lib, b"coraza_rules_add\0")?,
            rules_add_file: symbol(lib, b"coraza_rules_add_file\0")?,
            free_waf_config: symbol(lib, b"coraza_free_waf_config\0")?,
            new_waf: symbol(lib, b"coraza_new_waf\0")?,
            new_transaction: symbol(lib, b"coraza_new_transaction\0")?,
            process_connection: symbol(lib, b"coraza_process_connection\0")?,
            process_uri: symbol(lib, b"coraza_process_uri\0")?,
            add_request_header: symbol(lib, b"coraza_add_request_header\0")?,
            process_request_headers: symbol(lib, b"coraza_process_request_headers\0")?,
            append_request_body: symbol(lib, b"coraza_append_request_body\0")?,
            process_request_body: symbol(lib, b"coraza_process_request_body\0")?,
            intervention: symbol(lib, b"coraza_intervention\0")?,
            free_intervention: symbol(lib, b"coraza_free_intervention\0")?,
            free_transaction: symbol(lib, b"coraza_free_transaction\0")?,
            free_waf: symbol(lib, b"coraza_free_waf\0")?,
            rules_count: symbol(lib, b"coraza_rules_count\0")?,
            free_string: symbol(lib, b"coraza_free_string\0")?,
            process_logging: symbol(lib, b"coraza_process_logging\0")?,
        })
    }
}

unsafe fn symbol<T: Copy>(lib: &Library, name: &[u8]) -> Result<T, String> {
    let label = std::str::from_utf8(name)
        .unwrap_or("symbol")
        .trim_end_matches('\0');
    let loaded = unsafe { lib.get::<T>(name) }
        .map_err(|error| format!("libcoraza missing symbol {label}: {error}"))?;
    Ok(*loaded)
}

unsafe fn construct_waf(
    api: &Api,
    rules_path: Option<&Path>,
    directives: Option<&str>,
) -> Result<LoadedWaf, String> {
    let config = unsafe { (api.new_waf_config)() };
    if config == 0 {
        return Err("libcoraza failed to allocate a WAF config".to_string());
    }
    let config = ConfigGuard { api, config };
    if let Some(path) = rules_path {
        let path_c = c_string(&path.to_string_lossy())?;
        let rc = unsafe { (api.rules_add_file)(config.config, path_c.as_ptr()) };
        if rc == CORAZA_ERROR {
            return Err("libcoraza rejected CORAZA_RULES_PATH".to_string());
        }
    }
    if let Some(text) = directives.filter(|text| !text.trim().is_empty()) {
        let text_c = c_string(text)?;
        let rc = unsafe { (api.rules_add)(config.config, text_c.as_ptr()) };
        if rc == CORAZA_ERROR {
            return Err("libcoraza rejected CORAZA_DIRECTIVES".to_string());
        }
    }
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let waf = unsafe { (api.new_waf)(config.config, &mut err_ptr) };
    if !err_ptr.is_null() {
        let reason = unsafe { take_c_string(api, err_ptr) };
        return Err(format!("libcoraza failed to build WAF: {reason}"));
    }
    if waf == 0 {
        return Err("libcoraza failed to build WAF".to_string());
    }
    let rules = unsafe { (api.rules_count)(waf) };
    if rules <= 0 {
        unsafe {
            (api.free_waf)(waf);
        }
        return Err("libcoraza loaded an empty ruleset".to_string());
    }
    Ok(LoadedWaf { waf, rules })
}

struct ConfigGuard<'a> {
    api: &'a Api,
    config: usize,
}

impl Drop for ConfigGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            (self.api.free_waf_config)(self.config);
        }
    }
}

unsafe fn hit_from_intervention(
    api: &Api,
    tx: usize,
    uri: &str,
    client_ip: Option<IpAddr>,
) -> ProvenEngineOutcome {
    let ptr = unsafe { (api.intervention)(tx) };
    if ptr.is_null() {
        return ProvenEngineOutcome::Hit(CorazaIngestedHit {
            client_ip,
            action: "block".to_string(),
            reason: "coraza/crs: transaction interrupted".to_string(),
            score: 50,
            path: uri.to_string(),
            timestamp_unix: None,
        });
    }
    let it = unsafe { &*ptr };
    let action_raw = unsafe { optional_cstr(it.action) };
    let data = unsafe { optional_cstr(it.data) };
    let action = if action_raw == "deny"
        || action_raw == "drop"
        || action_raw.is_empty()
        || it.disruptive != 0
    {
        "block"
    } else {
        "monitor"
    };
    let mut reason = format!("coraza/crs: rule {}", it.rule_id);
    if !data.is_empty() {
        reason.push_str(": ");
        reason.push_str(&data);
    }
    let score = if action == "block" { 50 } else { 25 };
    unsafe {
        (api.free_intervention)(ptr);
    }
    ProvenEngineOutcome::Hit(CorazaIngestedHit {
        client_ip,
        action: action.to_string(),
        reason,
        score,
        path: uri.to_string(),
        timestamp_unix: None,
    })
}

unsafe fn optional_cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

unsafe fn take_c_string(api: &Api, ptr: *mut c_char) -> String {
    let text = unsafe { optional_cstr(ptr) };
    unsafe {
        (api.free_string)(ptr);
    }
    text
}

fn c_string(text: &str) -> Result<CString, String> {
    CString::new(text).map_err(|_| "coraza in-process input contained an interior NUL".to_string())
}

fn c_len(len: usize) -> Result<c_int, String> {
    c_int::try_from(len).map_err(|_| "coraza in-process body exceeds C int length".to_string())
}

#[cfg(test)]
pub(crate) fn load_stub_engine() -> std::sync::Arc<InProcessCoraza> {
    let lib = Path::new(env!("WARDNET_CORAZA_ABI_STUB"));
    let dir = std::env::temp_dir().join(format!(
        "wardnet-coraza-rules-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create rules dir");
    let rules = dir.join("crs.conf");
    std::fs::write(&rules, "SecRuleEngine On\n").expect("write rules fixture");
    std::sync::Arc::new(InProcessCoraza::load(lib, Some(&rules), None).expect("load stub"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_library_fails_closed() {
        let err = InProcessCoraza::load(
            Path::new("/no/such/libcoraza.so"),
            None,
            Some("SecRuleEngine On"),
        )
        .unwrap_err();
        assert!(
            err.contains("does not exist"),
            "missing library must fail before bind: {err}"
        );
    }

    #[test]
    fn library_without_rules_fails_closed() {
        let err = InProcessCoraza::load(Path::new(env!("WARDNET_CORAZA_ABI_STUB")), None, None)
            .unwrap_err();
        assert!(
            err.contains("CORAZA_RULES_PATH") || err.contains("CORAZA_DIRECTIVES"),
            "empty ruleset must not silently allow: {err}"
        );
    }

    #[test]
    fn stub_engine_blocks_crs_probe_and_allows_clean() {
        let engine = load_stub_engine();
        assert!(engine.rules() >= 1);
        match engine.evaluate("GET", "/app?crs-probe=1", "", None) {
            ProvenEngineOutcome::Hit(hit) => {
                assert_eq!(hit.action, "block");
                assert!(hit.reason.contains("942100"), "{}", hit.reason);
                assert_eq!(hit.path, "/app?crs-probe=1");
            }
            other => panic!("expected hit, got {other:?}"),
        }
        assert_eq!(
            engine.evaluate("GET", "/app?q=hello", "", None),
            ProvenEngineOutcome::Clean
        );
    }
}
