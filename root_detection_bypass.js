/**
 * Root Detection Bypass
 * Author: Uppula Abhiram — Mobile Security Researcher
 *
 * WHAT IT DOES:
 * Many Android apps refuse to run on rooted devices to prevent tampering
 * and reverse engineering. This script hooks the most common root detection
 * methods and makes the app believe it is running on a clean, unrooted device.
 *
 * USAGE:
 *   frida -U -n com.target.app -l root_detection_bypass.js
 *   frida -U --spawn com.target.app -l root_detection_bypass.js --no-pause
 *
 * TARGETS:
 *   - RootBeer library (most common third-party root detection)
 *   - File system checks (su binary, Magisk, SuperSU paths)
 *   - Build tag checks (test-keys)
 *   - System property checks
 *   - Runtime command execution checks
 */

setTimeout(function () {
    Java.perform(function () {
        console.log("\n[*] Root Detection Bypass — Uppula Abhiram");
        console.log("[*] Hooking root detection methods...\n");

        // ─────────────────────────────────────────────
        // 1. RootBeer — most widely used root detection library
        // ─────────────────────────────────────────────
        try {
            var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");

            RootBeer.isRooted.implementation = function () {
                console.log("[+] RootBeer.isRooted() → returning false");
                return false;
            };

            RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () {
                console.log("[+] RootBeer.isRootedWithoutBusyBoxCheck() → returning false");
                return false;
            };

            RootBeer.detectRootManagementApps.implementation = function () {
                console.log("[+] RootBeer.detectRootManagementApps() → returning false");
                return false;
            };

            RootBeer.detectPotentiallyDangerousApps.implementation = function () {
                console.log("[+] RootBeer.detectPotentiallyDangerousApps() → returning false");
                return false;
            };

            RootBeer.checkForSuBinary.implementation = function () {
                console.log("[+] RootBeer.checkForSuBinary() → returning false");
                return false;
            };

            console.log("[+] RootBeer library hooked");
        } catch (e) {
            console.log("[-] RootBeer not found: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 2. File existence checks — su binary, Magisk, SuperSU
        //    Apps often check if these paths exist on the filesystem
        // ─────────────────────────────────────────────
        try {
            var File = Java.use("java.io.File");

            // List of paths that root detection checks for
            var rootPaths = [
                "/system/app/Superuser.apk",
                "/sbin/su",
                "/system/bin/su",
                "/system/xbin/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/su",
                "/su/bin/su",
                "/magisk/.core/bin/su",
                "/sbin/.magisk",
                "/sbin/.core/mirror",
                "/data/adb/magisk.img",
                "/data/adb/magisk",
                "/cache/magisk.log",
            ];

            File.exists.implementation = function () {
                var filePath = this.getAbsolutePath();
                for (var i = 0; i < rootPaths.length; i++) {
                    if (filePath === rootPaths[i]) {
                        console.log("[+] File.exists() bypassed for root path: " + filePath);
                        return false; // Pretend the file doesn't exist
                    }
                }
                return this.exists(); // For non-root paths, return real result
            };

            console.log("[+] File.exists() hooked for root path checks");
        } catch (e) {
            console.log("[-] File.exists() hook failed: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 3. Build.TAGS check — rooted devices often have "test-keys"
        //    instead of "release-keys" in Build.TAGS
        // ─────────────────────────────────────────────
        try {
            var Build = Java.use("android.os.Build");
            Build.TAGS.value = "release-keys";
            console.log("[+] Build.TAGS set to release-keys");
        } catch (e) {
            console.log("[-] Build.TAGS modification failed: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 4. Runtime.exec — some apps run "which su" or "su" directly
        //    to check if the su binary is accessible
        // ─────────────────────────────────────────────
        try {
            var Runtime = Java.use("java.lang.Runtime");

            Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
                if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
                    console.log("[+] Runtime.exec() intercepted — blocking root check command: " + cmd);
                    // Return exec of a harmless command instead
                    return this.exec("echo clean");
                }
                return this.exec(cmd);
            };

            Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {
                for (var i = 0; i < cmds.length; i++) {
                    if (cmds[i] && (cmds[i].indexOf("su") !== -1)) {
                        console.log("[+] Runtime.exec([]) intercepted — root check command blocked");
                        return this.exec("echo clean");
                    }
                }
                return this.exec(cmds);
            };

            console.log("[+] Runtime.exec() hooked");
        } catch (e) {
            console.log("[-] Runtime.exec() hook failed: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 5. System property checks
        //    ro.debuggable and ro.secure are checked by some apps
        // ─────────────────────────────────────────────
        try {
            var SystemProperties = Java.use("android.os.SystemProperties");
            SystemProperties.get.overload("java.lang.String").implementation = function (key) {
                if (key === "ro.debuggable") {
                    console.log("[+] SystemProperties.get(ro.debuggable) → returning 0");
                    return "0";
                }
                if (key === "ro.secure") {
                    console.log("[+] SystemProperties.get(ro.secure) → returning 1");
                    return "1";
                }
                return this.get(key);
            };
            console.log("[+] SystemProperties.get() hooked");
        } catch (e) {
            console.log("[-] SystemProperties hook failed: " + e.message);
        }

        console.log("\n[*] Root Detection Bypass complete.");
        console.log("[*] App should now run as if on a clean device.\n");
    });
}, 0);
