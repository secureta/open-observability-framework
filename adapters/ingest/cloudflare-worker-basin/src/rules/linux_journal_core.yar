/*
 * Open Observability Framework (OOF) - Core Linux / systemd-journald YARA Rule Pack
 *
 * Compatible with YARA, YARA-X (CLI / host-agent), and boreal (Cloudflare Worker WASM).
 */

rule Linux_Reverse_Shell_Indicator : reverse_shell T1059_004 {
    meta:
        author = "open-observability-framework"
        severity = "CRITICAL"
        mitre_attack = "T1059.004"
        description = "Detects interactive Linux reverse shell command indicators in journald telemetry"
    strings:
        $dev_tcp = "/dev/tcp/" nocase
        $dev_udp = "/dev/udp/" nocase
        $bash_redir = "bash -i >&" nocase
        $nc_exec = /nc(\.traditional)?\s+.*-e\s+\/bin\/(ba)?sh/ nocase
        $mkfifo_nc = /mkfifo\s+.*\|\s*nc\s+/ nocase
        $socat_exec = /socat\s+.*exec:.*(bash|sh)/ nocase
    condition:
        any of them
}

rule Linux_Encoded_Command_Execution : defense_evasion T1027 {
    meta:
        author = "open-observability-framework"
        severity = "HIGH"
        mitre_attack = "T1027"
        description = "Detects base64-decoded payload execution piped into an interpreter"
    strings:
        $b64_pipe_sh = /base64\s+(-d|--decode)\s*\|\s*(\/bin\/)?(ba)?sh/ nocase
        $b64_pipe_script = /base64\s+(-d|--decode)\s*\|\s*(python[23]?|perl|ruby|node)/ nocase
        $echo_b64_pipe = /echo\s+[A-Za-z0-9+\/=]{16,}\s*\|\s*base64\s+(-d|--decode)/ nocase
        $py_b64_exec = /python[23]?\s+-c\s+["']import\s+base64/ nocase
    condition:
        any of them
}

rule Linux_Suspicious_Runtime_Injection : privilege_escalation T1574_006 {
    meta:
        author = "open-observability-framework"
        severity = "HIGH"
        mitre_attack = "T1574.006"
        description = "Detects shared object preloading, memfd execution, or /dev/shm staging indicators"
    strings:
        $ld_preload_env = "LD_PRELOAD="
        $ld_so_preload = "/etc/ld.so.preload"
        $memfd = "memfd:"
        $dev_shm = "/dev/shm/"
    condition:
        any of them
}

rule Linux_Credential_Access_Attempt : credential_access T1003 {
    meta:
        author = "open-observability-framework"
        severity = "HIGH"
        mitre_attack = "T1003"
        description = "Detects suspicious access to shadow credentials, kernel memory, or SSH authorized_keys tampering"
    strings:
        $shadow_file = "/etc/shadow"
        $mimipenguin = "mimipenguin" nocase
        $proc_kcore = "/proc/kcore"
        $auth_keys_append = />>\s*[^\s]*\.ssh\/authorized_keys/
        $ssh_keygen_tamper = /ssh-keygen\s+.*authorized_keys/ nocase
    condition:
        any of them
}
