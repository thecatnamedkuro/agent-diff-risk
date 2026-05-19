from agent_diff_risk.cli import score_diff


def test_flags_secret_and_auth_path():
    diff = """diff --git a/src/auth/session.py b/src/auth/session.py
--- a/src/auth/session.py
+++ b/src/auth/session.py
@@ -1,1 +1,3 @@
 old = 1
+API_KEY = "abcdefghijklmnop"
+def check(jwt): return jwt
"""
    score = score_diff(diff)
    assert score.level in {"high", "critical"}
    assert any("secret-looking" in f.message for f in score.findings)
    assert any("auth/security" in f.message for f in score.findings)


def test_low_when_source_without_tests():
    diff = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,1 +1,2 @@
 print('hi')
+print('bye')
"""
    score = score_diff(diff)
    assert score.points >= 1
    assert any("without nearby test" in f.message for f in score.findings)


def test_no_findings_for_empty_diff():
    score = score_diff("")
    assert score.level == "none"
    assert score.files_changed == 0
