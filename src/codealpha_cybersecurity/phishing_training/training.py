from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    id: str
    category: str
    message: str
    is_phishing: bool
    explanation: str


SCENARIOS = (
    Scenario("lookalike-domain", "email-recognition", "URGENT: Reset your mail password at http://micros0ft-support.example", True,
             "The lookalike domain, urgency, and non-HTTPS link are red flags. Open the known service independently instead."),
    Scenario("expected-invoice", "email-recognition", "Your approved vendor invoice is available in the authenticated vendor portal.", False,
             "An expected message that directs you to a known portal is lower risk; still verify sender context and invoice details."),
    Scenario("credential-request", "social-engineering", "IT needs your password immediately to prevent account closure. Reply with it now.", True,
             "Legitimate support teams do not request passwords by email. Report it through your organisation's security channel."),
    Scenario("qr-login", "fake-website-recognition", "A QR code on a poster says 'scan to keep your account active' and opens a login page at contoso-login.example.", True,
             "QR codes can conceal a destination. Verify the exact domain and use the official app or bookmarked site instead."),
    Scenario("payment-diversion", "social-engineering", "Your director texts from a new number: 'Buy gift cards now; I am in a meeting. Keep this confidential.'", True,
             "Secrecy, urgency, and an unverified new contact are impersonation signals. Verify using a known phone number."),
    Scenario("mfa-fatigue", "security-best-practices", "You receive repeated MFA prompts that you did not initiate; one says approve to stop the alerts.", True,
             "Never approve an unexpected MFA request. Deny it, change your password if needed, and notify security."),
    Scenario("shortened-link", "fake-website-recognition", "A delivery notice uses a shortened link and asks for card details to release a parcel you did not order.", True,
             "An unexpected delivery, shortened link, and payment request are strong red flags. Track orders through the carrier's official site."),
    Scenario("shared-document", "email-recognition", "A familiar colleague shares a document, but the login page asks for your password after you are already signed in.", True,
             "Unexpected re-authentication can indicate a credential-harvesting site. Verify the share through a separate channel."),
    Scenario("software-update", "security-best-practices", "A browser pop-up says your device is infected and offers a 'cleanup tool' download.", True,
             "Do not install software from pop-ups. Update through approved operating-system or organisation-managed channels."),
    Scenario("verified-helpdesk", "social-engineering", "After you opened a ticket, support replies in the authenticated help desk and asks you to use the password-reset workflow.", False,
             "Context and a known authenticated channel reduce risk. Still use the official reset link rather than a pasted credential request."),
)


def score_answers(answers: dict[str, bool]) -> dict[str, object]:
    """Score answers where True means the learner classified the scenario as phishing."""
    results = []
    correct = 0
    categories: dict[str, dict[str, int]] = {}
    for scenario in SCENARIOS:
        answer = answers.get(scenario.id)
        ok = answer is scenario.is_phishing
        correct += ok
        summary = categories.setdefault(scenario.category, {"correct": 0, "total": 0})
        summary["total"] += 1
        summary["correct"] += int(ok)
        results.append({"id": scenario.id, "category": scenario.category, "correct": ok, "explanation": scenario.explanation})
    total = len(SCENARIOS)
    guidance = (
        "Excellent: keep reporting suspicious messages and verify unexpected requests." if correct == total else
        "Review the explanations for missed scenarios. Practise verifying through known channels; never share passwords or approve unexpected MFA prompts."
    )
    return {"correct": correct, "total": total, "percentage": round(correct * 100 / total), "by_category": categories, "guidance": guidance, "results": results}
