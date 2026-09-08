from codealpha_cybersecurity.phishing_training.training import SCENARIOS, score_answers


def test_training_has_ten_or_more_cross_category_scenarios() -> None:
    assert len(SCENARIOS) >= 10
    assert {scenario.category for scenario in SCENARIOS} >= {
        "email-recognition", "fake-website-recognition", "social-engineering", "security-best-practices"
    }


def test_training_score_includes_category_feedback_and_guidance() -> None:
    result = score_answers({scenario.id: scenario.is_phishing for scenario in SCENARIOS})
    assert result["percentage"] == 100
    assert set(result["by_category"]) == {scenario.category for scenario in SCENARIOS}
    assert "Excellent" in result["guidance"]
