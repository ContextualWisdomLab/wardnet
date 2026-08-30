//! Test-only libcoraza C ABI fixture.
//!
//! Compiled as a cdylib by `build.rs`. It is not a WAF: it implements the
//! current libcoraza export surface so Wardnet can exercise in-process loading
//! without Go at CI build time. Interruptions fire for the documented
//! `crs-probe=1` contract used by the sidecar tests and for the hermetic
//! OWASP CRS attack battery (issue #11) that the live-gateway evidence test
//! fires at the real binary. Detection *quality* against real traffic stays
//! with an operator-supplied libcoraza + Core Rule Set; this fixture only
//! proves Wardnet's load → evaluate → block → record path end to end.

#![deny(warnings)]

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::{Mutex, OnceLock};

const CORAZA_ERROR: c_int = -1;
const CORAZA_OK: c_int = 0;
const CORAZA_INTERRUPTION: c_int = 1;

#[repr(C)]
// Fields are retained even when unread to mirror the external libcoraza ABI.
#[allow(dead_code)]
pub struct CorazaIntervention {
    action: *mut c_char,
    status: c_int,
    pause: c_int,
    disruptive: c_int,
    data: *mut c_char,
    rule_id: c_int,
}

struct Config {
    rules: i32,
}

struct Waf {
    rules: i32,
}

struct Tx {
    uri: String,
    headers: String,
    body: String,
    interrupted: bool,
    rule_id: i32,
    message: String,
}

/// One hermetic CRS battery entry: a lowercase substring needle, the OWASP
/// Core Rule Set rule id it stands for, and the canonical CRS message text.
/// First match wins, mirroring CRS phase ordering closely enough for the
/// deterministic evidence test.
struct BatteryEntry {
    needle: &'static str,
    rule_id: i32,
    message: &'static str,
}

const SQLI_MESSAGE: &str = "SQL Injection Attack Detected via libinjection";
const XSS_MESSAGE: &str = "XSS Attack Detected via libinjection";
const TRAVERSAL_MESSAGE: &str = "Path Traversal Attack (/../)";
const RCE_MESSAGE: &str = "Remote Command Execution: Unix Command Injection";
const LOG4J_MESSAGE: &str = "Log4j JNDI Remote Code Execution attempt";

const BATTERY: &[BatteryEntry] = &[
    BatteryEntry {
        needle: "crs-probe=1",
        rule_id: 942100,
        message: SQLI_MESSAGE,
    },
    BatteryEntry {
        needle: "crs-probe%3d1",
        rule_id: 942100,
        message: SQLI_MESSAGE,
    },
    BatteryEntry {
        needle: "' or '1'='1",
        rule_id: 942100,
        message: SQLI_MESSAGE,
    },
    BatteryEntry {
        needle: "%27%20or%20%271%27%3d%271",
        rule_id: 942100,
        message: SQLI_MESSAGE,
    },
    BatteryEntry {
        needle: "union select",
        rule_id: 942100,
        message: SQLI_MESSAGE,
    },
    BatteryEntry {
        needle: "union%20select",
        rule_id: 942100,
        message: SQLI_MESSAGE,
    },
    BatteryEntry {
        needle: "<script",
        rule_id: 941100,
        message: XSS_MESSAGE,
    },
    BatteryEntry {
        needle: "%3cscript",
        rule_id: 941100,
        message: XSS_MESSAGE,
    },
    BatteryEntry {
        needle: "onerror=alert",
        rule_id: 941100,
        message: XSS_MESSAGE,
    },
    // RCE and Log4j entries precede traversal entries because command
    // fixtures such as `; cat /etc/passwd` also contain traversal-looking
    // substrings; first-match ordering keeps rule attribution deterministic.
    BatteryEntry {
        needle: "; cat ",
        rule_id: 932100,
        message: RCE_MESSAGE,
    },
    BatteryEntry {
        needle: "%3b%20cat%20",
        rule_id: 932100,
        message: RCE_MESSAGE,
    },
    BatteryEntry {
        needle: "/bin/sh",
        rule_id: 932100,
        message: RCE_MESSAGE,
    },
    BatteryEntry {
        needle: "$(whoami)",
        rule_id: 932100,
        message: RCE_MESSAGE,
    },
    BatteryEntry {
        needle: "${jndi",
        rule_id: 944120,
        message: LOG4J_MESSAGE,
    },
    BatteryEntry {
        needle: "%24%7bjndi",
        rule_id: 944120,
        message: LOG4J_MESSAGE,
    },
    BatteryEntry {
        needle: "../",
        rule_id: 930100,
        message: TRAVERSAL_MESSAGE,
    },
    BatteryEntry {
        needle: "..%2f",
        rule_id: 930100,
        message: TRAVERSAL_MESSAGE,
    },
    BatteryEntry {
        needle: "..%252f",
        rule_id: 930100,
        message: TRAVERSAL_MESSAGE,
    },
    BatteryEntry {
        needle: "etc/passwd",
        rule_id: 930100,
        message: TRAVERSAL_MESSAGE,
    },
    BatteryEntry {
        needle: "etc%2fpasswd",
        rule_id: 930100,
        message: TRAVERSAL_MESSAGE,
    },
];

fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(needle)
}

/// Runs the battery over one phase's accumulated request text. Returns the
/// matched entry so each phase can mark the transaction with the same rule
/// id and message that `coraza_intervention` reports later.
fn battery_match(text: &str) -> Option<&'static BatteryEntry> {
    BATTERY.iter().find(|entry| contains_ignore_case(text, entry.needle))
}

struct Store {
    next: usize,
    configs: HashMap<usize, Config>,
    wafs: HashMap<usize, Waf>,
    txs: HashMap<usize, Tx>,
}

fn store() -> &'static Mutex<Store> {
    static STORE: OnceLock<Mutex<Store>> = OnceLock::new();
    STORE.get_or_init(|| {
        Mutex::new(Store {
            next: 1,
            configs: HashMap::new(),
            wafs: HashMap::new(),
            txs: HashMap::new(),
        })
    })
}

fn alloc_id(store: &mut Store) -> usize {
    let id = store.next;
    store.next += 1;
    id
}

fn c_str<'a>(ptr: *const c_char) -> Result<&'a str, ()> {
    if ptr.is_null() {
        return Err(());
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().map_err(|_| ())
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_new_waf_config() -> usize {
    let mut store = store().lock().expect("stub lock");
    let id = alloc_id(&mut store);
    store.configs.insert(id, Config { rules: 0 });
    id
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_rules_add(config: usize, _directives: *const c_char) -> c_int {
    let mut store = store().lock().expect("stub lock");
    match store.configs.get_mut(&config) {
        Some(item) => {
            item.rules += 1;
            CORAZA_OK
        }
        None => CORAZA_ERROR,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_rules_add_file(config: usize, file: *const c_char) -> c_int {
    let Ok(path) = c_str(file) else {
        return CORAZA_ERROR;
    };
    if !std::path::Path::new(path).is_file() {
        return CORAZA_ERROR;
    }
    let mut store = store().lock().expect("stub lock");
    match store.configs.get_mut(&config) {
        Some(item) => {
            item.rules += 1;
            CORAZA_OK
        }
        None => CORAZA_ERROR,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_free_waf_config(config: usize) -> c_int {
    let mut store = store().lock().expect("stub lock");
    store.configs.remove(&config);
    CORAZA_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_new_waf(config: usize, er: *mut *mut c_char) -> usize {
    if !er.is_null() {
        unsafe {
            *er = std::ptr::null_mut();
        }
    }
    let mut store = store().lock().expect("stub lock");
    let Some(cfg) = store.configs.get(&config) else {
        if !er.is_null() {
            let msg = CString::new("invalid waf config").expect("static error");
            unsafe {
                *er = msg.into_raw();
            }
        }
        return 0;
    };
    let rules = cfg.rules;
    let id = alloc_id(&mut store);
    store.wafs.insert(id, Waf { rules });
    id
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_new_transaction(waf: usize) -> usize {
    let mut store = store().lock().expect("stub lock");
    if !store.wafs.contains_key(&waf) {
        return 0;
    }
    let id = alloc_id(&mut store);
    store.txs.insert(
        id,
        Tx {
            uri: String::new(),
            headers: String::new(),
            body: String::new(),
            interrupted: false,
            rule_id: 0,
            message: String::new(),
        },
    );
    id
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_process_connection(
    _tx: usize,
    _source: *const c_char,
    _client_port: c_int,
    _server_host: *const c_char,
    _server_port: c_int,
) -> c_int {
    CORAZA_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_process_uri(
    tx: usize,
    uri: *const c_char,
    _method: *const c_char,
    _proto: *const c_char,
) -> c_int {
    let Ok(uri) = c_str(uri) else {
        return CORAZA_ERROR;
    };
    let mut store = store().lock().expect("stub lock");
    let Some(tx) = store.txs.get_mut(&tx) else {
        return CORAZA_ERROR;
    };
    tx.uri = uri.to_string();
    if let Some(entry) = battery_match(uri) {
        tx.interrupted = true;
        tx.rule_id = entry.rule_id;
        tx.message = entry.message.to_string();
    }
    CORAZA_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_add_request_header(
    tx: usize,
    name: *const c_char,
    _name_len: c_int,
    value: *const c_char,
    _value_len: c_int,
) -> c_int {
    let (Ok(name), Ok(value)) = (c_str(name), c_str(value)) else {
        return CORAZA_ERROR;
    };
    let mut store = store().lock().expect("stub lock");
    let Some(tx) = store.txs.get_mut(&tx) else {
        return CORAZA_ERROR;
    };
    tx.headers.push_str(name);
    tx.headers.push(':');
    tx.headers.push_str(value);
    tx.headers.push('\n');
    if let Some(entry) = battery_match(&tx.headers) {
        tx.interrupted = true;
        tx.rule_id = entry.rule_id;
        tx.message = entry.message.to_string();
    }
    CORAZA_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_process_request_headers(tx: usize) -> c_int {
    let store = store().lock().expect("stub lock");
    match store.txs.get(&tx) {
        Some(tx) if tx.interrupted => CORAZA_INTERRUPTION,
        Some(_) => CORAZA_OK,
        None => CORAZA_ERROR,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_append_request_body(
    tx: usize,
    data: *const u8,
    length: c_int,
) -> c_int {
    if length < 0 {
        return CORAZA_ERROR;
    }
    let bytes = if data.is_null() || length == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(data, length as usize) }
    };
    let Ok(chunk) = std::str::from_utf8(bytes) else {
        return CORAZA_ERROR;
    };
    let mut store = store().lock().expect("stub lock");
    let Some(tx) = store.txs.get_mut(&tx) else {
        return CORAZA_ERROR;
    };
    tx.body.push_str(chunk);
    if let Some(entry) = battery_match(&tx.body) {
        tx.interrupted = true;
        tx.rule_id = entry.rule_id;
        tx.message = entry.message.to_string();
    }
    CORAZA_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_process_request_body(tx: usize) -> c_int {
    let store = store().lock().expect("stub lock");
    match store.txs.get(&tx) {
        Some(tx) if tx.interrupted => CORAZA_INTERRUPTION,
        Some(_) => CORAZA_OK,
        None => CORAZA_ERROR,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_intervention(tx: usize) -> *mut CorazaIntervention {
    let store = store().lock().expect("stub lock");
    let Some(tx) = store.txs.get(&tx) else {
        return std::ptr::null_mut();
    };
    if !tx.interrupted {
        return std::ptr::null_mut();
    }
    let action = CString::new("deny").expect("static action");
    let data = CString::new(tx.message.clone())
        .expect("battery messages contain no interior NUL");
    let it = Box::new(CorazaIntervention {
        action: action.into_raw(),
        status: 403,
        pause: 0,
        disruptive: 1,
        data: data.into_raw(),
        rule_id: tx.rule_id,
    });
    Box::into_raw(it)
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_free_intervention(it: *mut CorazaIntervention) -> c_int {
    if it.is_null() {
        return CORAZA_ERROR;
    }
    unsafe {
        let it = Box::from_raw(it);
        if !it.action.is_null() {
            drop(CString::from_raw(it.action));
        }
        if !it.data.is_null() {
            drop(CString::from_raw(it.data));
        }
    }
    CORAZA_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_free_transaction(tx: usize) -> c_int {
    let mut store = store().lock().expect("stub lock");
    store.txs.remove(&tx);
    CORAZA_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_free_waf(waf: usize) -> c_int {
    let mut store = store().lock().expect("stub lock");
    store.wafs.remove(&waf);
    CORAZA_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_rules_count(waf: usize) -> c_int {
    let store = store().lock().expect("stub lock");
    store
        .wafs
        .get(&waf)
        .map(|waf| waf.rules)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_process_logging(_tx: usize) -> c_int {
    CORAZA_OK
}
