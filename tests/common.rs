//! Test data: sample diffs used across multiple test modules.

pub const CLEAN_DIFF: &str = "\
diff --git a/src/utils.py b/src/utils.py
index 1111111..2222222 100644
--- a/src/utils.py
+++ b/src/utils.py
@@ -10,6 +10,9 @@ def helper(x: int) -> str:
+def format_name(name: str) -> str:
+    return name.strip().title()
+
diff --git a/tests/test_utils.py b/tests/test_utils.py
new file mode 100644
--- /dev/null
+++ b/tests/test_utils.py
@@ -0,0 +1,5 @@
+def test_format_name():
+    assert format_name(\"  hello  \") == \"Hello\"
";

pub const VULNERABLE_DIFF: &str = "\
diff --git a/app/auth.py b/app/auth.py
new file mode 100644
--- /dev/null
+++ b/app/auth.py
@@ -0,0 +1,25 @@
+import sqlite3
+import os
+import hashlib
+
+def login(username, password):
+    conn = sqlite3.connect(\"users.db\")
+    cursor = conn.cursor()
+    query = \"SELECT * FROM users WHERE username='\" + username + \"'\"
+    cursor.execute(query)
+    return cursor.fetchone()
+
+API_KEY = \"sk-1234567890abcdef1234567890abcdef\"
+
+def run_command(user_input):
+    os.system(\"echo \" + user_input)
+    eval(user_input)
+
+def hash_password(password):
+    return hashlib.md5(password.encode()).hexdigest()
+
+def read_file(filename):
+    return open(\"../../etc/passwd\" + filename).read()
+
+SECRET_TOKEN = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz1234\"
diff --git a/templates/profile.html b/templates/profile.html
new file mode 100644
--- /dev/null
+++ b/templates/profile.html
@@ -0,0 +1,5 @@
+<div id=\"profile\">
+  <script>document.innerHTML = \"{{ user_bio }}\"</script>
+  <a href=\"http://example.com\">Insecure link</a>
+</div>
";

pub const EMPTY_DIFF: &str = "";
