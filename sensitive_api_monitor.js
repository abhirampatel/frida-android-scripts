/**
 * Sensitive API Monitor
 * Author: Uppula Abhiram — Mobile Security Researcher
 *
 * WHAT IT DOES:
 * Monitors all sensitive data access operations at runtime:
 *   - File read/write operations (captures file paths and content)
 *   - SharedPreferences access (captures keys and values stored)
 *   - Logcat output (captures sensitive data leaked to logs)
 *   - SQLite database queries (captures SQL and results)
 *   - Clipboard access (captures data copied to clipboard)
 *   - Network URL connections (captures all URLs before SSL)
 *
 * WHY THIS MATTERS:
 * Apps often store sensitive data in SharedPreferences, log tokens to Logcat,
 * or write credentials to files. This script gives you a real-time view of
 * every sensitive operation the app performs — without needing source code.
 *
 * USAGE:
 *   frida -U -n com.target.app -l sensitive_api_monitor.js
 *   frida -U --spawn com.target.app -l sensitive_api_monitor.js --no-pause
 *
 * TIP:
 *   Run this alongside ssl_pinning_bypass.js for complete visibility:
 *   frida -U -n com.target.app -l ssl_pinning_bypass.js -l sensitive_api_monitor.js
 */

function timestamp() {
    return new Date().toISOString().substr(11, 12);
}

function truncate(str, maxLen) {
    if (!str) return "null";
    var s = str.toString();
    return s.length > maxLen ? s.substring(0, maxLen) + "..." : s;
}

setTimeout(function () {
    Java.perform(function () {
        console.log("\n[*] Sensitive API Monitor — Uppula Abhiram");
        console.log("[*] Monitoring file access, SharedPreferences, logs, SQLite...\n");

        // ─────────────────────────────────────────────
        // 1. SharedPreferences — most common sensitive data store
        //    Captures every key-value pair read or written
        // ─────────────────────────────────────────────
        try {
            var SharedPreferencesEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

            SharedPreferencesEditor.putString.implementation = function (key, value) {
                console.log("[" + timestamp() + "] [SharedPrefs WRITE]");
                console.log("    Key   : " + key);
                console.log("    Value : " + truncate(value, 200));
                return this.putString(key, value);
            };

            SharedPreferencesEditor.putInt.implementation = function (key, value) {
                console.log("[" + timestamp() + "] [SharedPrefs WRITE int]");
                console.log("    Key   : " + key + " = " + value);
                return this.putInt(key, value);
            };

            SharedPreferencesEditor.putBoolean.implementation = function (key, value) {
                console.log("[" + timestamp() + "] [SharedPrefs WRITE bool]");
                console.log("    Key   : " + key + " = " + value);
                return this.putBoolean(key, value);
            };

            console.log("[+] SharedPreferences.Editor hooked");
        } catch (e) {
            console.log("[-] SharedPreferences.Editor hook failed: " + e.message);
        }

        try {
            var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");

            SharedPreferencesImpl.getString.implementation = function (key, defValue) {
                var result = this.getString(key, defValue);
                if (result !== null && result !== defValue) {
                    console.log("[" + timestamp() + "] [SharedPrefs READ]");
                    console.log("    Key   : " + key);
                    console.log("    Value : " + truncate(result, 200));
                }
                return result;
            };

            console.log("[+] SharedPreferences read hooked");
        } catch (e) {
            console.log("[-] SharedPreferences read hook failed: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 2. Android Log — captures sensitive data leaked to Logcat
        //    Developers often log tokens, passwords during development
        //    and forget to remove them before release
        // ─────────────────────────────────────────────
        try {
            var Log = Java.use("android.util.Log");
            var logMethods = ["d", "e", "i", "v", "w"];

            logMethods.forEach(function (method) {
                Log[method].overload("java.lang.String", "java.lang.String").implementation = function (tag, msg) {
                    // Only print if message contains potentially sensitive content
                    var lower = msg.toLowerCase();
                    var sensitive = ["token", "key", "password", "secret", "auth", "bearer",
                        "session", "credential", "email", "phone", "user"];
                    var isSensitive = sensitive.some(function (s) { return lower.indexOf(s) !== -1; });

                    if (isSensitive) {
                        console.log("[" + timestamp() + "] [LOG." + method.toUpperCase() + " ⚠️  SENSITIVE]");
                        console.log("    Tag : " + tag);
                        console.log("    Msg : " + truncate(msg, 300));
                    }
                    return Log[method](tag, msg);
                };
            });

            console.log("[+] android.util.Log hooked");
        } catch (e) {
            console.log("[-] Log hook failed: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 3. File I/O — captures file paths and content
        //    Useful for finding where the app stores sensitive data
        // ─────────────────────────────────────────────
        try {
            var FileOutputStream = Java.use("java.io.FileOutputStream");

            FileOutputStream.$init.overload("java.io.File", "boolean").implementation = function (file, append) {
                var path = file.getAbsolutePath();
                // Filter for app-relevant paths only
                if (path.indexOf("/data/data") !== -1 || path.indexOf("/sdcard") !== -1) {
                    console.log("[" + timestamp() + "] [FILE WRITE]");
                    console.log("    Path   : " + path);
                    console.log("    Append : " + append);
                }
                return this.$init(file, append);
            };

            console.log("[+] FileOutputStream hooked");
        } catch (e) {
            console.log("[-] FileOutputStream hook failed: " + e.message);
        }

        try {
            var FileInputStream = Java.use("java.io.FileInputStream");

            FileInputStream.$init.overload("java.io.File").implementation = function (file) {
                var path = file.getAbsolutePath();
                if (path.indexOf("/data/data") !== -1 || path.indexOf("/sdcard") !== -1) {
                    console.log("[" + timestamp() + "] [FILE READ]");
                    console.log("    Path : " + path);
                }
                return this.$init(file);
            };

            console.log("[+] FileInputStream hooked");
        } catch (e) {
            console.log("[-] FileInputStream hook failed: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 4. SQLite — captures database queries and results
        //    Useful for finding insecure data storage and SQL injection
        // ─────────────────────────────────────────────
        try {
            var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

            SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function (sql, selectionArgs) {
                console.log("[" + timestamp() + "] [SQLite rawQuery]");
                console.log("    SQL  : " + truncate(sql, 300));
                if (selectionArgs) {
                    console.log("    Args : " + selectionArgs.join(", "));
                }
                return this.rawQuery(sql, selectionArgs);
            };

            SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function (sql) {
                console.log("[" + timestamp() + "] [SQLite execSQL]");
                console.log("    SQL : " + truncate(sql, 300));
                return this.execSQL(sql);
            };

            console.log("[+] SQLiteDatabase hooked");
        } catch (e) {
            console.log("[-] SQLiteDatabase hook failed: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 5. Clipboard — captures data copied to clipboard
        //    Passwords and tokens are often copied here
        // ─────────────────────────────────────────────
        try {
            var ClipboardManager = Java.use("android.content.ClipboardManager");

            ClipboardManager.setPrimaryClip.implementation = function (clip) {
                console.log("[" + timestamp() + "] [CLIPBOARD WRITE]");
                try {
                    var item = clip.getItemAt(0);
                    console.log("    Content : " + truncate(item.getText(), 200));
                } catch (e) { }
                return this.setPrimaryClip(clip);
            };

            console.log("[+] ClipboardManager hooked");
        } catch (e) {
            console.log("[-] ClipboardManager hook failed: " + e.message);
        }

        // ─────────────────────────────────────────────
        // 6. URL Connections — captures all network URLs
        //    Runs before SSL, so captures even HTTPS destinations
        // ─────────────────────────────────────────────
        try {
            var URL = Java.use("java.net.URL");

            URL.openConnection.overload().implementation = function () {
                console.log("[" + timestamp() + "] [NETWORK URL]");
                console.log("    URL : " + this.toString());
                return this.openConnection();
            };

            console.log("[+] URL.openConnection() hooked");
        } catch (e) {
            console.log("[-] URL.openConnection() hook failed: " + e.message);
        }

        console.log("\n[*] Sensitive API Monitor active.");
        console.log("[*] All sensitive operations will be logged above.\n");
    });
}, 0);
