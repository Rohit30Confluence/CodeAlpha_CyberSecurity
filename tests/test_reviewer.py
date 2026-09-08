from codealpha_cybersecurity.secure_coding_review.reviewer import review_source


def test_reviewer_finds_eval_and_shell_true() -> None:
    findings = review_source("import subprocess\neval(user_input)\nsubprocess.run('ls', shell=True)\n")
    assert {f.rule for f in findings} == {"S001", "S004"}


def test_reviewer_ignores_safe_subprocess_default() -> None:
    assert review_source("import subprocess\nsubprocess.run(['echo', 'ok'])\n") == []
