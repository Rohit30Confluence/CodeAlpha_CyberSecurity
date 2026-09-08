from codealpha_cybersecurity.secure_coding_review.reviewer import review_source


def test_reviewer_reports_pickle_and_exec_with_remediation() -> None:
    findings = review_source("import pickle\nexec('x = 1')\npickle.loads(data)\n")
    assert {finding.rule for finding in findings} == {"S002", "S003"}
    assert all(finding.remediation for finding in findings)
