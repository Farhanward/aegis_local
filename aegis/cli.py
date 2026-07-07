from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .batch import evaluate_intents
from .crypto import ensure_keypair
from .datasets import convert_neuralchemy_to_intents
from .gate import decide
from .ledger import DEFAULT_LEDGER, append_record, verify_ledger
from .models import ToolIntent
from .policy import DEFAULT_POLICY, load_policy, write_default_policy
from .reports import batch_markdown
from .runner import run_intent


def load_intent(path: str | Path) -> ToolIntent:
    return ToolIntent.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def gate_command(args: argparse.Namespace) -> int:
    intent = load_intent(args.input)
    decision = decide(intent, policy=load_policy(args.policy))
    payload = {"intent": intent.to_dict(), "decision": decision.to_dict()}
    if args.record:
        payload["ledger"] = append_record(payload, ledger_path=args.ledger)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 2 if args.fail_on_block and decision.action in {"BLOCK", "QUARANTINE"} else 0


def verify_command(args: argparse.Namespace) -> int:
    result = verify_ledger(args.ledger)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


def init_command(args: argparse.Namespace) -> int:
    private, public = ensure_keypair(args.private_key, args.public_key)
    policy = write_default_policy(args.policy)
    print(json.dumps({"private_key": str(private.resolve()), "public_key": str(public.resolve()), "policy": str(policy.resolve())}, ensure_ascii=False, indent=2))
    return 0


def run_command(args: argparse.Namespace) -> int:
    intent = load_intent(args.input)
    result = run_intent(intent, policy=load_policy(args.policy), ledger_path=args.ledger, record=not args.no_record)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 2 if args.fail_on_block and result.decision.action in {"BLOCK", "QUARANTINE", "REVIEW"} else 0


def make_benchmark_command(args: argparse.Namespace) -> int:
    result = convert_neuralchemy_to_intents(args.source, args.out)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def batch_command(args: argparse.Namespace) -> int:
    report = evaluate_intents(args.input, limit=args.limit, repeat=args.repeat, policy_path=args.policy)
    payload = json.dumps(report, ensure_ascii=False, indent=2) if args.format == "json" else batch_markdown(report)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload, encoding="utf-8")
        print(str(out_path.resolve()))
    else:
        print(payload)
    return 1 if report.get("errors") else 0


def serve_command(args: argparse.Namespace) -> int:
    from .service import run_server

    run_server(host=args.host, port=args.port)
    return 0


def version_command(args: argparse.Namespace) -> int:
    from .version import __version__

    print(json.dumps({"service": "aegis", "version": __version__}, ensure_ascii=False))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="aegis", description="Verifiable local agent gate.")
    sub = root.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Create Ed25519 keypair if missing.")
    init.add_argument("--private-key", default="keys/aegis_ed25519_private.pem")
    init.add_argument("--public-key", default="keys/aegis_ed25519_public.pem")
    init.add_argument("--policy", default=str(DEFAULT_POLICY))
    init.set_defaults(func=init_command)

    gate = sub.add_parser("gate", help="Evaluate a tool intent and optionally record it.")
    gate.add_argument("--input", required=True)
    gate.add_argument("--policy", default=str(DEFAULT_POLICY))
    gate.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    gate.add_argument("--record", action="store_true")
    gate.add_argument("--fail-on-block", action="store_true")
    gate.set_defaults(func=gate_command)

    run = sub.add_parser("run", help="Gate, execute only if allowed, and record a signed run result.")
    run.add_argument("--input", required=True)
    run.add_argument("--policy", default=str(DEFAULT_POLICY))
    run.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    run.add_argument("--no-record", action="store_true")
    run.add_argument("--fail-on-block", action="store_true")
    run.set_defaults(func=run_command)

    bench = sub.add_parser("make-benchmark", help="Convert internet prompt-injection data into AEGIS tool intents.")
    bench.add_argument("--source", default="C:/Projects/almunaa/data/benchmarks/neuralchemy_prompt_injection_full.events.jsonl")
    bench.add_argument("--out", default="data/benchmarks/aegis_neuralchemy_tool_intents.jsonl")
    bench.set_defaults(func=make_benchmark_command)

    batch = sub.add_parser("batch", help="Evaluate JSONL tool intents.")
    batch.add_argument("--input", required=True)
    batch.add_argument("--policy", default=str(DEFAULT_POLICY))
    batch.add_argument("--out")
    batch.add_argument("--format", choices=["json", "md"], default="md")
    batch.add_argument("--limit", type=int)
    batch.add_argument("--repeat", type=int, default=1)
    batch.set_defaults(func=batch_command)

    stress = sub.add_parser("stress", help="Repeated batch evaluation for collapse testing.")
    stress.add_argument("--input", required=True)
    stress.add_argument("--policy", default=str(DEFAULT_POLICY))
    stress.add_argument("--out")
    stress.add_argument("--format", choices=["json", "md"], default="md")
    stress.add_argument("--limit", type=int)
    stress.add_argument("--repeat", type=int, default=3)
    stress.set_defaults(func=batch_command)

    verify = sub.add_parser("verify-ledger", help="Verify signed hash-chain ledger.")
    verify.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    verify.set_defaults(func=verify_command)

    serve = sub.add_parser("serve", help="Run the local HTTP gate service (decisions only, no execution).")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.set_defaults(func=serve_command)

    version = sub.add_parser("version", help="Print service version.")
    version.set_defaults(func=version_command)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
