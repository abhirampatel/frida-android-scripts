/**
 * SSL Pinning Bypass
 * Author: Uppula Abhiram — Mobile Security Researcher
 * 
 * WHAT IT DOES:
 * Most production Android apps implement SSL certificate pinning to prevent
 * traffic interception. This script hooks into the core SSL validation methods
 * and disables certificate verification, allowing you to intercept HTTPS traffic
 * through Burp Suite or any proxy.
 *
 * USAGE:
 *   frida -U -n com.target.app -l ssl_pinning_bypass.js
 *   frida -U --spawn com.target.app -l ssl_pinning_bypass.js
 *
 * TARGETS:
 *   - OkHttp3 CertificatePinner (most common)
 *   - TrustManagerImpl (Android core)
 *   - HttpsURLConnection
 *   - Custom X509TrustManager implementations
 *
 * AFTER RUNNING:
 *   Set your proxy to 127.0.0.1:8080 and intercept with Burp Suite.
 */

setTimeout(function () {
    Java.perform(function () {
        console.log("\n[*] SSL Pinning Bypass — Uppula Abhiram");
        console.log("[*] Hooking SSL validation methods...\n");

        // ─────────────────────────────────────────────
        // 1. OkHttp3 CertificatePinner — most widely used
        // ─────────────────────────────────────────────
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
                console.log("[+] OkHttp3 CertificatePinner.check() bypassed for: " + hostname);
                return; // Do nothing — skip the pin check
            };
            console.log("[+] OkHttp3 CertificatePinner hooked");
        } catch (e) {
            console.log("[-] OkHttp3 CertificatePinner not found: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 2. OkHttp3 older overload (some apps use this signature)
        // ─────────────────────────────────────────────
        try {
            var CertificatePinner2 = Java.use("okhttp3.CertificatePinner");
            CertificatePinner2.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function (hostname, certs) {
                console.log("[+] OkHttp3 CertificatePinner.check() [v2] bypassed for: " + hostname);
                return;
            };
        } catch (e) {
            console.log("[-] OkHttp3 CertificatePinner v2 not found");
        }

        // ─────────────────────────────────────────────
        // 3. Android TrustManagerImpl — core SSL validation
        // ─────────────────────────────────────────────
        try {
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                console.log("[+] TrustManagerImpl.verifyChain() bypassed for: " + host);
                return untrustedChain; // Return the chain as-is without verification
            };
            console.log("[+] TrustManagerImpl hooked");
        } catch (e) {
            console.log("[-] TrustManagerImpl not found: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 4. Generic X509TrustManager — catches custom implementations
        // ─────────────────────────────────────────────
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");

            // Build a TrustManager that trusts everything
            var TrustManager = Java.registerClass({
                name: "com.bypass.TrustManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) { },
                    checkServerTrusted: function (chain, authType) {
                        console.log("[+] X509TrustManager.checkServerTrusted() bypassed");
                    },
                    getAcceptedIssuers: function () {
                        return [];
                    }
                }
            });

            var TrustManagers = [TrustManager.$new()];
            var SSLContextObj = SSLContext.getInstance("TLS");
            SSLContextObj.init(null, TrustManagers, null);
            console.log("[+] Custom X509TrustManager installed");
        } catch (e) {
            console.log("[-] X509TrustManager override failed: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 5. HttpsURLConnection — fallback for older apps
        // ─────────────────────────────────────────────
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
                console.log("[+] HttpsURLConnection.setDefaultHostnameVerifier() bypassed");
                return;
            };
            console.log("[+] HttpsURLConnection hooked");
        } catch (e) {
            console.log("[-] HttpsURLConnection not found: " + e.message);
        }

        console.log("\n[*] SSL Pinning Bypass complete.");
        console.log("[*] Configure your proxy to intercept traffic.\n");
    });
}, 0);
