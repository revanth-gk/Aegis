# Attack Log Format — Sentinel-Core Pipeline

This document describes exactly what the pipeline logs for each attack type,
enabling the team to verify real events are flowing through the system.

---

## 1. External Payload Download via `curl`

| Field         | Value                                     |
|---------------|-------------------------------------------|
| **Syscall**   | `connect`                                 |
| **Process**   | `curl`                                    |
| **File Path** | Target URL (e.g., `http://evil.example.com/payload.sh`) |
| **Pod Name**  | `attacker-pod`                            |
| **Namespace** | `default`                                 |
| **GUIDE Grade** | `TP`                                    |
| **Confidence** | `0.95–0.99`                              |
| **MITRE Technique** | `T1071.001` — Application Layer Protocol: Web Protocols |
| **MITRE Tactic**    | Command and Control                   |

**raw_event mapping:**
```json
{
  "process": "curl",
  "syscall": "connect",
  "file_path": "http://evil.example.com/payload.sh",
  "pod_name": "attacker-pod",
  "namespace": "default",
  "user": "root",
  "pid": 1042,
  "alert_title": "Suspicious connect from curl"
}
```

---

## 2. `/etc/shadow` Read (Credential Access)

| Field         | Value                                     |
|---------------|-------------------------------------------|
| **Syscall**   | `openat`                                  |
| **Process**   | `cat`                                     |
| **File Path** | `/etc/shadow`                             |
| **Pod Name**  | `attacker-pod`                            |
| **Namespace** | `default`                                 |
| **GUIDE Grade** | `TP`                                    |
| **Confidence** | `0.97–0.99`                              |
| **MITRE Technique** | `T1003.008` — OS Credential Dumping: /etc/passwd and /etc/shadow |
| **MITRE Tactic**    | Credential Access                     |

**raw_event mapping:**
```json
{
  "process": "cat",
  "syscall": "openat",
  "file_path": "/etc/shadow",
  "pod_name": "attacker-pod",
  "namespace": "default",
  "user": "root",
  "pid": 1043,
  "alert_title": "Suspicious openat from cat on /etc/shadow"
}
```

---

## 3. Reverse Shell via `nc`

| Field         | Value                                     |
|---------------|-------------------------------------------|
| **Syscall**   | `connect` + `execve`                      |
| **Process**   | `nc` (or `sh` spawning `nc`)              |
| **File Path** | Target IP:Port (e.g., `10.0.0.99:4444`)  |
| **Pod Name**  | `attacker-pod`                            |
| **Namespace** | `default`                                 |
| **GUIDE Grade** | `TP`                                    |
| **Confidence** | `0.98–0.99`                              |
| **MITRE Technique** | `T1059.004` — Command and Scripting Interpreter: Unix Shell |
| **MITRE Tactic**    | Execution                             |

Tetragon captures two events for this attack:
1. `execve` for the `sh -c` wrapper
2. `connect` for the outbound TCP connection to `10.0.0.99:4444`

**raw_event mapping:**
```json
{
  "process": "nc",
  "syscall": "connect",
  "file_path": "10.0.0.99:4444",
  "pod_name": "attacker-pod",
  "namespace": "default",
  "user": "root",
  "pid": 1044,
  "alert_title": "Suspicious connect from nc (reverse shell)"
}
```

---

## 4. Process Enumeration via `ps aux`

| Field         | Value                                     |
|---------------|-------------------------------------------|
| **Syscall**   | `execve`                                  |
| **Process**   | `ps`                                      |
| **File Path** | `/bin/ps`                                 |
| **Pod Name**  | `attacker-pod`                            |
| **Namespace** | `default`                                 |
| **GUIDE Grade** | `BP`                                    |
| **Confidence** | `0.60–0.75`                              |
| **MITRE Technique** | `T1057` — Process Discovery           |
| **MITRE Tactic**    | Discovery                             |

**raw_event mapping:**
```json
{
  "process": "ps",
  "syscall": "execve",
  "file_path": "/bin/ps",
  "pod_name": "attacker-pod",
  "namespace": "default",
  "user": "root",
  "pid": 1045,
  "alert_title": "Suspicious execve from ps"
}
```

---

## 5. DNS Exfiltration Attempt

| Field         | Value                                     |
|---------------|-------------------------------------------|
| **Syscall**   | `connect` (UDP port 53)                   |
| **Process**   | `nslookup`                                |
| **File Path** | `evil.example.com` (query target)         |
| **Pod Name**  | `attacker-pod`                            |
| **Namespace** | `default`                                 |
| **GUIDE Grade** | `TP`                                    |
| **Confidence** | `0.85–0.95`                              |
| **MITRE Technique** | `T1048.003` — Exfiltration Over Unencrypted Non-C2 Protocol |
| **MITRE Tactic**    | Exfiltration                          |

**raw_event mapping:**
```json
{
  "process": "nslookup",
  "syscall": "connect",
  "file_path": "evil.example.com:53",
  "pod_name": "attacker-pod",
  "namespace": "default",
  "user": "root",
  "pid": 1046,
  "alert_title": "Suspicious DNS query to evil.example.com"
}
```

---

## Expected Terminal Output

When `./start_app.sh` runs and events flow through the pipeline, the terminal shows:

```
============================================================
  SENTINEL-CORE LIVE PIPELINE
============================================================
[NODE A] event_router       | grade=TP  | score=0.97 | 2ms
[NODE B] rag_retriever      | mitre=412 chars | azure=287 chars | 340ms
[NODE C] report_generator   | report=198 words | yaml=23 lines | 1840ms
------------------------------------------------------------
THREAT NEUTRALIZED
  Process  : curl
  Syscall  : connect
  Pod      : attacker-pod / default
  Grade    : TP (97.0% confidence)
  MITRE    : T1071.001 (Application Layer Protocol: Web Protocols)
  Report   : [Blocked outbound connection from 'curl'...]
  YAML Fix : NetworkPolicy applied to restrict egress
============================================================
```
