"""Offline CLI for native DRW/1 JSON rules and normalized JSON Lines fixtures."""
import argparse
import json
from pathlib import Path
from engine import MAX_EVENT_BYTES, MAX_RULE_BYTES, ValidationError, run, to_csv


def read_bounded(path, limit):
    with Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValidationError(f'{Path(path).name}: file exceeds {limit} bytes.')
    return raw.decode('utf-8-sig')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rule', required=True)
    parser.add_argument('--events', required=True)
    parser.add_argument('--baseline')
    parser.add_argument('--output', default='reports')
    args = parser.parse_args()
    try:
        report = run(read_bounded(args.rule, MAX_RULE_BYTES), read_bounded(args.events, MAX_EVENT_BYTES),
                     read_bounded(args.baseline, MAX_RULE_BYTES) if args.baseline else None)
        out = Path(args.output)
        out.mkdir(parents=True, exist_ok=True)
        (out / 'rule-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        (out / 'rule-events.csv').write_text('\ufeff' + to_csv(report), encoding='utf-8', newline='')
        print(f"{report['status']}: {report['input']['valid_events']} valid events; {report['candidate']['matches']} candidate matches.")
        print(f'Reports: {out.resolve()}')
    except (OSError, UnicodeError, ValidationError) as exc:
        parser.exit(1, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
