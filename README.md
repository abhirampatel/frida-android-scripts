# Frida Android Scripts

A collection of production-ready Frida instrumentation scripts for Android security research and penetration testing. Each script is documented with what it does, why it matters, and exactly how to use it.

**Author:** Uppula Abhiram — Mobile Security Researcher  
**LinkedIn:** https://www.linkedin.com/in/abhiram-patel-09a778244  
**Blog:** https://medium.com/@uppulaabhirampatel2601  
**APK Scanner:** https://github.com/abhirampatel/android-security-toolkit

---

## Scripts

| Script | Purpose | Key Target |
|--------|---------|------------|
| `ssl_pinning_bypass.js` | Bypass SSL certificate pinning | OkHttp3, TrustManagerImpl, HttpsURLConnection |
| `root_detection_bypass.js` | Bypass root detection | RootBeer, file checks, Build.TAGS, Runtime.exec |
| `crypto_hooker.js` | Capture encryption keys and plaintext at runtime | Cipher, Mac, MessageDigest, SecretKeyFactory |
| `sensitive_api_monitor.js` | Monitor all sensitive data access | SharedPreferences, SQLite, File I/O, Logcat, Clipboard |

---

## Requirements

```bash
# Frida installed on your machine
pip install frida-tools

# Frida server running on your rooted Android device
# Download matching version from: https://github.com/frida/frida/releases
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verify connection
frida-ls-devices
```

---

## Usage

### Run against a running app
```bash
frida -U -n com.target.app -l ssl_pinning_bypass.js
```

### Spawn and instrument from launch
```bash
frida -U --spawn com.target.app -l ssl_pinning_bypass.js --no-pause
```

### Run multiple scripts together
```bash
frida -U -n com.target.app -l ssl_pinning_bypass.js -l sensitive_api_monitor.js
```

### Find the exact package name of an app
```bash
frida-ps -Ua
```

---

## Script Details

---

### 1. ssl_pinning_bypass.js

**What it does:**  
Most production Android apps implement SSL certificate pinning to prevent traffic interception. This script hooks the core SSL validation methods and disables certificate verification — allowing you to intercept HTTPS traffic through Burp Suite or any proxy.

**Targets:**
- OkHttp3 CertificatePinner (most common in modern apps)
- Android TrustManagerImpl (core system SSL)
- Custom X509TrustManager implementations
- HttpsURLConnection (older apps)

**After running:**  
Set Burp Suite proxy to `127.0.0.1:8080` on your machine, configure the device Wi-Fi proxy to match, and all HTTPS traffic will be intercepted.

```bash
frida -U -n com.target.app -l ssl_pinning_bypass.js
```

---

### 2. root_detection_bypass.js

**What it does:**  
Many Android apps refuse to run on rooted devices to prevent reverse engineering and tampering. This script hooks the most common root detection methods and makes the app believe it is running on a clean, unrooted device.

**Targets:**
- RootBeer library — most widely used third-party root detection
- File existence checks — su binary, Magisk, SuperSU file paths
- Build.TAGS — `test-keys` vs `release-keys` check
- Runtime.exec — `which su` and direct `su` execution checks
- SystemProperties — `ro.debuggable` and `ro.secure`

```bash
frida -U --spawn com.target.app -l root_detection_bypass.js --no-pause
```

---

### 3. crypto_hooker.js

**What it does:**  
Hooks Android's cryptographic APIs at runtime and captures encryption keys, IVs, plaintext, and hashing inputs — at the exact moment they are used.

**Why this matters:**  
Apps that fetch encryption keys from a server at runtime and never store them on disk are completely invisible to static analysis. This script captures those keys regardless of where they came from.

**Captures:**
- `Cipher.init()` → algorithm name, key (hex + string), IV
- `Cipher.doFinal()` → input plaintext, output ciphertext (and vice versa)
- `Mac.init()` / `doFinal()` → HMAC key and output
- `MessageDigest` → hash input and output
- `SecretKeyFactory` → PBKDF2 passwords and iteration counts

```bash
frida -U -n com.target.app -l crypto_hooker.js
```

**Sample output:**
```
[14:23:11.442] ═══ Cipher.init() ═══
    Algorithm : AES/CBC/PKCS5Padding
    Mode      : ENCRYPT
    Key (hex) : 2b7e151628aed2a6abf7158809cf4f3c
    Key (str) : +~.(a..¦.q...O<
    IV  (hex) : 000102030405060708090a0b0c0d0e0f

[14:23:11.443] ═══ Cipher.doFinal() ═══
    Input  str : {"password":"hunter2","user":"admin"}
    Output hex : 7a9f3c2e...
```

---

### 4. sensitive_api_monitor.js

**What it does:**  
Monitors all sensitive data access operations in real time — giving you a complete picture of what data the app reads, writes, stores, and transmits during a session.

**Monitors:**
- `SharedPreferences` read and write — captures every key-value pair
- `android.util.Log` — captures log messages containing sensitive keywords (token, password, auth, etc.)
- `FileInputStream` / `FileOutputStream` — captures file paths accessed in the app data directory
- `SQLiteDatabase` — captures raw SQL queries and arguments
- `ClipboardManager` — captures data copied to clipboard
- `URL.openConnection()` — captures all network destinations before SSL

```bash
frida -U -n com.target.app -l sensitive_api_monitor.js
```

**Combine with SSL bypass for full coverage:**
```bash
frida -U -n com.target.app -l ssl_pinning_bypass.js -l sensitive_api_monitor.js
```

---

## Methodology

These scripts cover Phase 2 (Dynamic Analysis) of a full Android security assessment. For the complete methodology — including static analysis, native binary analysis with Binary Ninja, and local file analysis:

**Read:** [Android Application Security Testing: A Practical Methodology](https://medium.com/@uppulaabhirampatel2601/android-application-security-testing-a-practical-methodology-445e6d9815c5)

**Static analysis tool:** [android-security-toolkit](https://github.com/abhirampatel/android-security-toolkit)

---

## Legal Notice

These scripts are intended for authorized security testing only. Only use on applications and devices you own or have explicit written permission to test. The author is not responsible for misuse.

---

## License

MIT License — free to use, modify, and distribute with attribution.
