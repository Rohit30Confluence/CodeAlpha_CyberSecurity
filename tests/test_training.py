from codealpha_cybersecurity.phishing_training.training import SCENARIOS, score_answers


def test_perfect_quiz_score() -> None:
    result = score_answers({s.id: s.is_phishing for s in SCENARIOS})
    assert result["percentage"] == 100
    assert result["correct"] == len(SCENARIOS)
