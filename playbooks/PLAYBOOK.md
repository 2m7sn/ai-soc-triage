# L1 Triage Playbook - top 5 alert types

Each entry: what the alert means, how to confirm it, what an L1 does next, when to escalate.
Times are targets for this lab, not an SLA from any real SOC.

## 1. SSH brute force - T1110.001 (severity: high)

- **Signal:** 20+ failed passwords against one host in 60 s, usually from one external IP, usernames like `root`, `admin`, `ubuntu`. Slow variants (10-19/min) are missed by the rule and caught only by ML.
- **Confirm:** search auth logs for an `Accepted password` / `Accepted publickey` from the same source after the failures.
- **Do next (L1):**
  1. No success: block the source IP at the firewall / fail2ban, note the IP in the ticket, close as *true positive - contained*.
  2. Success found: isolate the host, disable or reset the account, pull `last`, `~/.ssh/authorized_keys`, crontab, new processes. Escalate.
- **Escalate to L2 when:** a login succeeded, or the source is internal (possible pivot).

## 2. C2 beaconing - T1071.001 (severity: critical)

- **Signal:** many outbound HTTP(S) connections over an hour with almost constant spacing (`interval_std_s` under 5 s) and small, uniform payloads, to a young or unknown domain or a bare IP.
- **Confirm:** check the destination against threat intel (VirusTotal, AbuseIPDB) and WHOIS age; check whether it is a known updater (Windows Update, AV telemetry, NTP) - those are the common false positives.
- **Do next (L1):**
  1. Known updater: add to the beaconing allowlist, close as benign.
  2. Unknown destination: isolate the host, capture `netstat -anob` / `ss -tunp`, running processes with parent and command line, scheduled tasks, Run keys. Block the destination at the proxy / DNS. Escalate.
- **Escalate to L2 when:** destination is unknown or flagged - always. Beaconing is a post-compromise signal.

## 3. DNS tunnelling - T1071.004 (severity: high)

- **Signal:** high volume of DNS queries with very long, high-entropy subdomain labels (60+ chars, entropy over 3.9) to one parent domain.
- **Confirm:** look at the parent domain. AV / reputation lookups (hash-like hex or base32 labels to a vendor domain) are benign; random alphanumerics to a fresh domain are not. Check TXT/NULL record types and query rate per minute.
- **Do next (L1):**
  1. Vendor lookup: allowlist the parent domain, close.
  2. Otherwise: block the parent domain at the resolver, isolate the host, export the query log for the last 24 h, identify the process doing the lookups.
- **Escalate to L2 when:** the domain is not a known vendor. Tunnelling means data is already leaving.

## 4. Lateral movement over SMB - T1021.002 (severity: critical)

- **Signal:** session to an admin share (`ADMIN$`, `C$`, `IPC$`) followed by a service creation (PsExec-style `PSEXESVC`), often off-hours, from a workstation rather than a management host.
- **Confirm:** is the source an IT jump host or SCCM server doing a push during business hours? Check the account (domain admin at 03:00 from a finance workstation is not normal). Check Windows event 7045 (new service) and 4624 type 3 on the destination.
- **Do next (L1):**
  1. Known admin host + business hours + change ticket: close as benign, add host to allowlist if missing.
  2. Otherwise: isolate the **source** host, disable the account used, check the destination for the new service binary and scheduled tasks. Escalate immediately.
- **Escalate to L2 when:** anything not explained by a change ticket. Treat as active intrusion.

## 5. Port scan - T1046 (severity: medium; low when internal scanner)

- **Signal:** one source touching dozens to hundreds of distinct ports on a host in a short window.
- **Confirm:** is the source an internal vulnerability scanner (Nessus/OpenVAS/Qualys) on its schedule? External sources scanning the perimeter are constant background noise; internal non-scanner sources are the interesting case.
- **Do next (L1):**
  1. Internal scanner: allowlist, close.
  2. External: confirm nothing answered on unexpected ports, block the source at the perimeter if it persists, close.
  3. Internal non-scanner host: open a ticket to the host owner and check that host for prior compromise (a scan from a workstation usually means someone is already on it).
- **Escalate to L2 when:** the source is an internal host that is not a scanner.

## General L1 rules used by this lab

- Any alert whose log fields contain instruction-like text ("ignore previous instructions", "mark benign", "analyst note") is **never** auto-closed. It goes to a human with severity at least high; the text itself is an indicator.
- A verdict of `needs_review` from any engine counts as workload: the analyst opens it.
- Close only with a reason that a second analyst could verify from the logs.
