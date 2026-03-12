/**
 * Cryptographic Function Hooker
 * Author: Uppula Abhiram — Mobile Security Researcher
 *
 * WHAT IT DOES:
 * Hooks Android's core cryptographic APIs at runtime and captures:
 *   - Encryption keys and initialization vectors (IVs)
 *   - Plaintext before encryption
 *   - Plaintext after decryption
 *   - Hashing inputs and outputs
 *   - Key generation parameters
 *
 * WHY THIS MATTERS:
 * Apps that fetch encryption keys from a server at runtime and never store
 * them on disk are invisible to static analysis. This script captures those
 * keys at the exact moment they are used — regardless of where they came from.
 *
 * USAGE:
 *   frida -U -n com.target.app -l crypto_hooker.js
 *   frida -U --spawn com.target.app -l crypto_hooker.js --no-pause
 *
 * OUTPUT:
 *   All captured keys, IVs, and plaintext are printed to the Frida console
 *   with timestamps and algorithm names.
 */

// ─────────────────────────────────────────────
// HELPER — convert byte arrays to hex strings
// for readable output
// ─────────────────────────────────────────────
function bytesToHex(byteArray) {
    if (!byteArray) return "null";
    try {
        var hex = "";
        for (var i = 0; i < byteArray.length; i++) {
            var b = (byteArray[i] & 0xFF).toString(16);
            hex += (b.length === 1 ? "0" : "") + b;
        }
        return hex;
    } catch (e) {
        return "[failed to convert bytes: " + e.message + "]";
    }
}

function bytesToString(byteArray) {
    if (!byteArray) return "null";
    try {
        var str = "";
        for (var i = 0; i < byteArray.length; i++) {
            var c = byteArray[i] & 0xFF;
            str += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
        }
        return str;
    } catch (e) {
        return "[failed to convert: " + e.message + "]";
    }
}

function timestamp() {
    return new Date().toISOString().substr(11, 12);
}

// ─────────────────────────────────────────────

setTimeout(function () {
    Java.perform(function () {
        console.log("\n[*] Crypto Hooker — Uppula Abhiram");
        console.log("[*] Hooking cryptographic APIs...\n");

        // ─────────────────────────────────────────────
        // 1. javax.crypto.Cipher — core encryption/decryption
        //    Hooks init() to capture keys and IVs
        //    Hooks doFinal() to capture plaintext and ciphertext
        // ─────────────────────────────────────────────
        try {
            var Cipher = Java.use("javax.crypto.Cipher");

            // Hook Cipher.init() — captures algorithm, key, and IV
            Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (opMode, key, params) {
                var modeStr = opMode === 1 ? "ENCRYPT" : opMode === 2 ? "DECRYPT" : "OTHER(" + opMode + ")";
                var algorithm = this.getAlgorithm();

                console.log("\n[" + timestamp() + "] ═══ Cipher.init() ═══");
                console.log("    Algorithm : " + algorithm);
                console.log("    Mode      : " + modeStr);

                try {
                    var keyBytes = key.getEncoded();
                    console.log("    Key (hex) : " + bytesToHex(keyBytes));
                    console.log("    Key (str) : " + bytesToString(keyBytes));
                } catch (e) {
                    console.log("    Key       : [could not extract]");
                }

                try {
                    // Extract IV from IvParameterSpec
                    var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
                    var ivSpec = Java.cast(params, IvParameterSpec);
                    var iv = ivSpec.getIV();
                    console.log("    IV  (hex) : " + bytesToHex(iv));
                } catch (e) {
                    console.log("    IV        : [not IvParameterSpec or not present]");
                }

                return this.init(opMode, key, params);
            };

            // Hook Cipher.init() without AlgorithmParameterSpec (no IV)
            Cipher.init.overload("int", "java.security.Key").implementation = function (opMode, key) {
                var modeStr = opMode === 1 ? "ENCRYPT" : opMode === 2 ? "DECRYPT" : "OTHER";
                console.log("\n[" + timestamp() + "] ═══ Cipher.init() [no IV] ═══");
                console.log("    Algorithm : " + this.getAlgorithm());
                console.log("    Mode      : " + modeStr);
                try {
                    var keyBytes = key.getEncoded();
                    console.log("    Key (hex) : " + bytesToHex(keyBytes));
                } catch (e) { }
                return this.init(opMode, key);
            };

            // Hook Cipher.doFinal() — captures plaintext and ciphertext
            Cipher.doFinal.overload("[B").implementation = function (input) {
                var result = this.doFinal(input);
                console.log("\n[" + timestamp() + "] ═══ Cipher.doFinal() ═══");
                console.log("    Algorithm  : " + this.getAlgorithm());
                console.log("    Input  hex : " + bytesToHex(input));
                console.log("    Input  str : " + bytesToString(input));
                console.log("    Output hex : " + bytesToHex(result));
                console.log("    Output str : " + bytesToString(result));
                return result;
            };

            console.log("[+] javax.crypto.Cipher hooked");
        } catch (e) {
            console.log("[-] Cipher hook failed: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 2. javax.crypto.Mac — HMAC operations
        //    Used for message authentication codes
        // ─────────────────────────────────────────────
        try {
            var Mac = Java.use("javax.crypto.Mac");

            Mac.init.overload("java.security.Key").implementation = function (key) {
                console.log("\n[" + timestamp() + "] ═══ Mac.init() ═══");
                console.log("    Algorithm : " + this.getAlgorithm());
                try {
                    console.log("    Key (hex) : " + bytesToHex(key.getEncoded()));
                } catch (e) { }
                return this.init(key);
            };

            Mac.doFinal.overload("[B").implementation = function (input) {
                var result = this.doFinal(input);
                console.log("\n[" + timestamp() + "] ═══ Mac.doFinal() ═══");
                console.log("    Input  : " + bytesToString(input));
                console.log("    HMAC   : " + bytesToHex(result));
                return result;
            };

            console.log("[+] javax.crypto.Mac (HMAC) hooked");
        } catch (e) {
            console.log("[-] Mac hook failed: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 3. java.security.MessageDigest — hashing
        //    Captures what is being hashed (MD5, SHA-1, SHA-256)
        // ─────────────────────────────────────────────
        try {
            var MessageDigest = Java.use("java.security.MessageDigest");

            MessageDigest.update.overload("[B").implementation = function (input) {
                console.log("\n[" + timestamp() + "] ═══ MessageDigest.update() ═══");
                console.log("    Algorithm : " + this.getAlgorithm());
                console.log("    Input str : " + bytesToString(input));
                console.log("    Input hex : " + bytesToHex(input));
                return this.update(input);
            };

            MessageDigest.digest.overload().implementation = function () {
                var result = this.digest();
                console.log("    Hash      : " + bytesToHex(result));
                return result;
            };

            console.log("[+] java.security.MessageDigest hooked");
        } catch (e) {
            console.log("[-] MessageDigest hook failed: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 4. javax.crypto.SecretKeyFactory — key derivation
        //    Captures passwords used in PBKDF2 key derivation
        // ─────────────────────────────────────────────
        try {
            var SecretKeyFactory = Java.use("javax.crypto.SecretKeyFactory");
            SecretKeyFactory.generateSecret.implementation = function (keySpec) {
                console.log("\n[" + timestamp() + "] ═══ SecretKeyFactory.generateSecret() ═══");
                console.log("    Algorithm : " + this.getAlgorithm());
                try {
                    var PBEKeySpec = Java.use("javax.crypto.spec.PBEKeySpec");
                    var pbeSpec = Java.cast(keySpec, PBEKeySpec);
                    var password = pbeSpec.getPassword();
                    console.log("    Password  : " + password.toString());
                    console.log("    Iterations: " + pbeSpec.getIterationCount());
                    console.log("    Key length: " + pbeSpec.getKeyLength() + " bits");
                } catch (e) {
                    console.log("    KeySpec   : [not PBEKeySpec]");
                }
                return this.generateSecret(keySpec);
            };
            console.log("[+] SecretKeyFactory hooked");
        } catch (e) {
            console.log("[-] SecretKeyFactory hook failed: " + e.message);
        }

        console.log("\n[*] Crypto Hooker active — waiting for cryptographic operations...\n");
    });
}, 0);
