from __future__ import annotations

import argparse
import json
from pathlib import Path

from .network_sniffer.sniffer import capture
from .phishing_training.training import SCENARIOS, score_answers
from .secure_coding_review.reviewer import review_file


def main() -> None:
    parser = argparse.ArgumentParser(description="CodeAlpha defensive cybersecurity task tools")
    sub = parser.add_subparsers(dest="command", required=True)
    cap = sub.add_parser("sniff", help="Bounded metadata-only capture on an authorised interface")
    cap.add_argument("--interface"); cap.add_argument("--count", type=int, default=10); cap.add_argument("--timeout", type=int, default=15)
    sub.add_parser("phishing-quiz", help="Run the local phishing-awareness quiz")
    review = sub.add_parser("review", help="Review a Python source file for selected risky patterns")
    review.add_argument("path", type=Path)
    args = parser.parse_args()
    if args.command == "sniff":
        print(json.dumps([packet.to_dict() for packet in capture(args.interface, args.count, args.timeout)], indent=2))
    elif args.command == "review":
        print(json.dumps([finding.to_dict() for finding in review_file(args.path)], indent=2))
    else:
        answers: dict[str, bool] = {}
        for s in SCENARIOS:
            print(f"\n{s.message}\nIs this phishing? [y/n]")
            answers[s.id] = input("> ").strip().lower() in {"y", "yes"}
        print(json.dumps(score_answers(answers), indent=2))


if __name__ == "__main__":
    main()
