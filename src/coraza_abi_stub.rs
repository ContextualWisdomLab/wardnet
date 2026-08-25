//! Test-only libcoraza C ABI fixture.
//!
//! Compiled as a cdylib by `build.rs`. It is not a WAF: it implements the
//! current libcoraza export surface so Wardnet can exercise in-process loading
//! without Go at CI build time. Interruptions fire only for the documented
//! `crs-probe=1` contract used by the sidecar tests.

#![deny(warnings)]

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::{Mutex, OnceLock};

const CORAZA_ERROR: c_int = -1;
const CORAZA_OK: c_int = 0;
const CORAZA_INTERRUPTION: c_int = 1;

#[repr(C)]
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
    interrupted: bool,
    rule_id: i32,
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
            interrupted: false,
            rule_id: 0,
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
    if uri.contains("crs-probe=1") {
        tx.interrupted = true;
        tx.rule_id = 942100;
    }
    CORAZA_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn coraza_add_request_header(
    _tx: usize,
    _name: *const c_char,
    _name_len: c_int,
    _value: *const c_char,
    _value_len: c_int,
) -> c_int {
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
    _tx: usize,
    _data: *const u8,
    _length: c_int,
) -> c_int {
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
    let data = CString::new("SQL Injection Attack Detected via libinjection")
        .expect("static data");
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
