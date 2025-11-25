# Vulnerability Scan Report

**Report ID:** `vuln-report-eb3e0ddc`
**Generated:** 2025-11-23T00:24:31.573409
**Target:** `us-central1-docker.pkg.dev/google-samples/microservices-demo/paymentservice:v0.10.3`
**Report Level:** EXECUTIVE

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Vulnerabilities | 37 |
| Critical | 🔴 2 |
| High | 🟠 11 |
| Medium | 🟡 14 |
| Low | 🔵 10 |
| Negligible | 🟢 0 |
| Vulnerable Packages | 19 |
| Average CVSS Score | 5.65 |
| Highest CVSS Score | 9.40 |
| Vulnerabilities with Fix | ✅ 22 |
| Vulnerabilities without Fix | ❌ 15 |

### Severity Distribution

```
Critical   ██ 2
High       ██████████████ 11
Medium     ██████████████████ 14
Low        █████████████ 10
Negligible  0
```

---

## Most Vulnerable Packages

| Package | Version | Vulnerabilities | Highest Severity | Recommended Version |
|---------|---------|-----------------|------------------|---------------------|
| `libcrypto3` | `3.3.2-r0` | 6 | 🟠 HIGH | `3.3.3-r0` |
| `libssl3` | `3.3.2-r0` | 6 | 🟠 HIGH | `3.3.3-r0` |
| `nodejs` | `20.15.1-r0` | 5 | 🟠 HIGH | `No fix available` |
| `busybox` | `1.36.1-r29` | 2 | 🔵 LOW | `No fix available` |
| `busybox-binsh` | `1.36.1-r29` | 2 | 🔵 LOW | `No fix available` |
| `ssl_client` | `1.36.1-r29` | 2 | 🔵 LOW | `No fix available` |
| `brace-expansion` | `1.1.11` | 2 | 🔵 LOW | `1.1.12` |
| `taffydb` | `2.6.2` | 1 | 🟠 HIGH | `No fix available` |
| `parse-duration` | `1.0.2` | 1 | 🟠 HIGH | `2.1.3` |
| `tar` | `6.1.12` | 1 | 🟡 MEDIUM | `6.2.1` |

## Critical & High Severity Vulnerabilities

### 🔴 GHSA-fjxv-7rqg-78g4

**Package:** `form-data@2.5.1`
**Severity:** CRITICAL
**CVSS Score:** 9.4
**Fix Available:** ✅ Upgrade to `2.5.4`

**Description:** form-data uses unsafe random function in form-data for choosing boundary

### 🔴 GHSA-2jcg-qqmg-46q6

**Package:** `monorepo-symlink-test@0.0.0`
**Severity:** CRITICAL
**CVSS Score:** N/A
**Fix Available:** ❌ No fix available

**Description:** Malware in monorepo-symlink-test

### 🟠 CVE-2025-31498

**Package:** `c-ares@1.33.1-r0`
**Severity:** HIGH
**CVSS Score:** 8.3
**Fix Available:** ❌ No fix available

**Description:** c-ares is an asynchronous resolver library. From 1.32.3 through 1.34.4, there is a use-after-free in read_answers() when process_answer() may re-enqueue a query either due to a DNS Cookie Failure or when the upstream server does not properly support EDNS, or possibly on TCP queries if the remote closed the connection immediately after a response. If there was an issue trying to put that new transaction on the wire, it would close the connection handle, but read_answers() was still expecting the connection handle to be available to possibly dequeue other responses. In theory a remote attacker might be able to trigger this by flooding the target with ICMP UNREACHABLE packets if they also control the upstream nameserver and can return a result with one of those conditions, this has been untested. Otherwise only a local attacker might be able to change system behavior to make send()/write() return a failure condition. This vulnerability is fixed in 1.34.5.

**References:**
- https://github.com/c-ares/c-ares/commit/29d38719112639d8c0ba910254a3dd4f482ea2d1
- https://github.com/c-ares/c-ares/pull/821
- https://github.com/c-ares/c-ares/security/advisories/GHSA-6hxc-62jh-p29v

### 🟠 CVE-2025-26519

**Package:** `musl@1.2.5-r0`
**Severity:** HIGH
**CVSS Score:** 8.1
**Fix Available:** ✅ Upgrade to `1.2.5-r1`

**Description:** No description available

### 🟠 CVE-2025-26519

**Package:** `musl-utils@1.2.5-r0`
**Severity:** HIGH
**CVSS Score:** 8.1
**Fix Available:** ✅ Upgrade to `1.2.5-r1`

**Description:** No description available

### 🟠 CVE-2025-23083

**Package:** `nodejs@20.15.1-r0`
**Severity:** HIGH
**CVSS Score:** 7.7
**Fix Available:** ❌ No fix available

**Description:** With the aid of the diagnostics_channel utility, an event can be hooked into whenever a worker thread is created. This is not limited only to workers but also exposes internal workers, where an instance of them can be fetched, and its constructor can be grabbed and reinstated for malicious usage. 

This vulnerability affects Permission Model users (--permission) on Node.js v20, v22, and v23.

**References:**
- https://nodejs.org/en/blog/vulnerability/january-2025-security-releases
- https://security.netapp.com/advisory/ntap-20250228-0008/
- https://www.vicarius.io/vsociety/posts/cve-2025-23083-detect-nodejs-vulnerability

### 🟠 GHSA-mxhp-79qh-mcx6

**Package:** `taffydb@2.6.2`
**Severity:** HIGH
**CVSS Score:** 7.5
**Fix Available:** ❌ No fix available

**Description:** TaffyDB can allow access to any data items in the DB

### 🟠 GHSA-hcrg-fc28-fcg5

**Package:** `parse-duration@1.0.2`
**Severity:** HIGH
**CVSS Score:** 7.5
**Fix Available:** ✅ Upgrade to `2.1.3`

**Description:** parse-duration has a Regex Denial of Service that results in event loop delay and out of memory

### 🟠 CVE-2025-23166

**Package:** `nodejs@20.15.1-r0`
**Severity:** HIGH
**CVSS Score:** 7.5
**Fix Available:** ❌ No fix available

**Description:** The C++ method SignTraits::DeriveBits() may incorrectly call ThrowException() based on user-supplied inputs when executing in a background thread, crashing the Node.js process. Such cryptographic operations are commonly applied to untrusted inputs. Thus, this mechanism potentially allows an adversary to remotely crash a Node.js runtime.

**References:**
- https://nodejs.org/en/blog/vulnerability/may-2025-security-releases

### 🟠 CVE-2025-9230

**Package:** `libcrypto3@3.3.2-r0`
**Severity:** HIGH
**CVSS Score:** 7.5
**Fix Available:** ✅ Upgrade to `3.3.5-r0`

**Description:** No description available

### 🟠 CVE-2025-9230

**Package:** `libssl3@3.3.2-r0`
**Severity:** HIGH
**CVSS Score:** 7.5
**Fix Available:** ✅ Upgrade to `3.3.5-r0`

**Description:** No description available

### 🟠 CVE-2025-5222

**Package:** `icu-data-en@74.2-r0`
**Severity:** HIGH
**CVSS Score:** 7
**Fix Available:** ✅ Upgrade to `74.2-r1`

**Description:** No description available

### 🟠 CVE-2025-5222

**Package:** `icu-libs@74.2-r0`
**Severity:** HIGH
**CVSS Score:** 7
**Fix Available:** ✅ Upgrade to `74.2-r1`

**Description:** No description available

## Remediation Recommendations

1. Upgrade 11 packages with available security patches
2. Implement compensating controls for 8 packages without fixes
3. Priority: Upgrade libcrypto3 from 3.3.2-r0 to 3.3.3-r0
4. Priority: Upgrade libssl3 from 3.3.2-r0 to 3.3.3-r0
5. Conduct regular vulnerability scans to track new issues
6. Implement automated dependency updates where possible

---

*Report generated by Threat Radar on 2025-11-23 00:24:31*