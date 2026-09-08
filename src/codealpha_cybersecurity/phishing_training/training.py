from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    id: str
    message: str
    is_phishing: bool
    explanation: str


SCENARIOS = (
    Scenario("lookalike-domain", "URGENT: Reset your mail password at http://micros0ft-support.example", True,
             "The lookalike domain, urgency, and non-HTTPS link are red flags."),
    Scenario("expected-invoice", "Your approved vendor invoice is available in the authenticated vendor portal.", False,
             "An expected message that directs you to a known portal is lower risk; still verify sender context."),
    Scenario("credential-request", "IT needs your password immediately to prevent account closure. Reply with it now.", True,
             "Legitimate support teams do not request passwords by email."),
)


def score_answers(answers: dict[str, bool]) -> dict[str, object]:
    """Score answers where True means the learner classified the scenario as phishing."""
    results = []
    correct = 0
    for scenario in SCENARIOS:
        answer = answers.get(scenario.id)
        ok = answer is scenario.is_phishing
        correct += ok
        results.append({"id": scenario.id, "correct": ok, "explanation": scenario.explanation})
    total = len(SCENARIOS)
    return {"correct": correct, "total": total, "percentage": round(correct * 100 / total), "results": results}
