"""DRW/1: a bounded local detection-rule evaluator, not a Sigma implementation."""
import csv
import hashlib
import io
import json
import re
import uuid
from datetime import datetime, timezone

MAX_EVENTS = 1000
MAX_EVENT_BYTES = 1024 * 1024
MAX_RULE_BYTES = 32768
MAX_WORK = 20_000_000
NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,39}\Z')
FIELD = re.compile(r'[A-Za-z_][A-Za-z0-9_.]{0,79}\Z')
OPS = {'eq', 'contains', 'startswith', 'endswith', 'exists'}


class ValidationError(ValueError):
    pass


def utf8(text):
    try:
        return text.encode('utf-8')
    except UnicodeError as exc:
        raise ValidationError('Input text contains invalid Unicode surrogate characters.') from exc


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f'Duplicate JSON key: {key[:80]}')
        result[key] = value
    return result


def load_json(text):
    try:
        return json.loads(text, object_pairs_hook=no_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValidationError('Non-finite JSON number.')))
    except ValidationError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValidationError('Invalid JSON. Use double-quoted strings and no trailing commas.') from exc


class Condition:
    """Recursive-descent boolean parser. No eval, regex conditions or code execution."""
    def __init__(self, text, names):
        if not isinstance(text, str) or not text or len(text) > 512:
            raise ValidationError('condition must be a non-empty string up to 512 characters.')
        self.tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*|[()]|\S', text)
        if len(self.tokens) > 64:
            raise ValidationError('condition has more than 64 tokens.')
        self.index, self.names, self.used = 0, set(names), set()
        self.tree = self.expression(0)
        if self.index != len(self.tokens):
            raise ValidationError('Unexpected condition token; only and, or, not and parentheses are supported.')
        if self.used != self.names:
            raise ValidationError('Every selection must appear in condition; remove unused selections.')

    def peek(self):
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def expression(self, depth):
        node = self.conjunction(depth)
        while self.peek() == 'or':
            self.index += 1
            node = ('or', node, self.conjunction(depth))
        return node

    def conjunction(self, depth):
        node = self.atom(depth)
        while self.peek() == 'and':
            self.index += 1
            node = ('and', node, self.atom(depth))
        return node

    def atom(self, depth):
        if depth > 16:
            raise ValidationError('condition nesting exceeds 16 levels.')
        token = self.peek()
        self.index += 1
        if token == 'not':
            return ('not', self.atom(depth + 1))
        if token == '(':
            node = self.expression(depth + 1)
            if self.peek() != ')':
                raise ValidationError('Unclosed condition parenthesis.')
            self.index += 1
            return node
        if token not in self.names:
            raise ValidationError(f'Unknown selection or unsupported condition token: {str(token)[:80]}')
        self.used.add(token)
        return ('selection', token)

    def matches(self, values, node=None):
        node = self.tree if node is None else node
        if node[0] == 'selection':
            return values[node[1]]
        if node[0] == 'not':
            return not self.matches(values, node[1])
        left, right = self.matches(values, node[1]), self.matches(values, node[2])
        return left and right if node[0] == 'and' else left or right


def valid_string(value, label, limit):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValidationError(f'{label} must be a non-empty string up to {limit} characters.')


def parse_rule(text):
    if not isinstance(text, str) or len(utf8(text)) > MAX_RULE_BYTES:
        raise ValidationError('Rule exceeds 32 KiB or is not text.')
    rule = load_json(text)
    keys = {'format', 'id', 'title', 'description', 'level', 'logsource', 'selections', 'condition'}
    if not isinstance(rule, dict) or set(rule) != keys:
        raise ValidationError('Rule requires exactly: format, id, title, description, level, logsource, selections, condition.')
    if rule['format'] != 'drw/1':
        raise ValidationError('Only the drw/1 native profile is supported. Sigma/YAML is not imported.')
    try:
        uuid.UUID(rule['id'])
    except (ValueError, TypeError, AttributeError):
        raise ValidationError('id must be a UUID string.') from None
    valid_string(rule['title'], 'title', 160)
    valid_string(rule['description'], 'description', 1000)
    if rule['level'] not in ('informational', 'low', 'medium', 'high', 'critical'):
        raise ValidationError('Unsupported level. This is author-supplied metadata, not a measured risk score.')
    source = rule['logsource']
    if not isinstance(source, dict) or set(source) != {'product', 'category'}:
        raise ValidationError('logsource requires exactly product and category.')
    for value in source.values():
        valid_string(value, 'logsource value', 80)
    groups = rule['selections']
    if not isinstance(groups, dict) or not 1 <= len(groups) <= 8:
        raise ValidationError('Supply 1..8 selections.')
    compiled = {}
    for name, fields in groups.items():
        if not NAME.fullmatch(name) or name in ('and', 'or', 'not'):
            raise ValidationError('Selection names must be identifiers, excluding and/or/not.')
        if not isinstance(fields, dict) or not 1 <= len(fields) <= 8:
            raise ValidationError('Each selection requires 1..8 field predicates.')
        compiled[name] = []
        for key, expected in fields.items():
            parts = key.split('|')
            field, modifiers = parts[0], parts[1:]
            if not FIELD.fullmatch(field) or len(modifiers) != len(set(modifiers)):
                raise ValidationError('Invalid field name or repeated modifier.')
            if any(m not in OPS | {'all'} for m in modifiers):
                raise ValidationError(f'Unsupported modifier in {key[:80]}. No regex, wildcards, numeric comparisons or conversions.')
            operators = [m for m in modifiers if m != 'all']
            if len(operators) > 1:
                raise ValidationError('Use at most one operator and optional all modifier.')
            op = operators[0] if operators else 'eq'
            values = expected if isinstance(expected, list) else [expected]
            if not 1 <= len(values) <= 16 or ('all' in modifiers and not isinstance(expected, list)):
                raise ValidationError('Values must have 1..16 items; all requires a list.')
            if op == 'exists':
                if type(expected) is not bool or modifiers != ['exists']:
                    raise ValidationError('exists requires a single Boolean and no other modifiers.')
            else:
                for value in values:
                    if type(value) not in (str, int, bool) or (type(value) is int and abs(value) > 2**63 - 1):
                        raise ValidationError('Rule values must be strings, signed 64-bit integers or Booleans; use exists for presence.')
                    if isinstance(value, str) and (not value or len(value) > 256):
                        raise ValidationError('Rule string values must have 1..256 characters.')
                    if isinstance(value, str) and any(c in value for c in '*?'):
                        raise ValidationError('Wildcard characters are unsupported. Use contains, startswith or endswith.')
                    if op != 'eq' and not isinstance(value, str):
                        raise ValidationError('Text operators require string values.')
            compiled[name].append((field, op, values, 'all' in modifiers, key))
    return rule, compiled, Condition(rule['condition'], compiled)


def parse_events(text):
    if not isinstance(text, str) or len(utf8(text)) > MAX_EVENT_BYTES:
        raise ValidationError('Event input must be UTF-8 JSON Lines text up to 1 MiB.')
    lines = text.lstrip('\ufeff').splitlines()
    if len(lines) > MAX_EVENTS:
        raise ValidationError('At most 1000 physical input lines are supported, including blank lines.')
    events, diagnostics, blanks = [], [], 0
    for index, line in enumerate(lines, 1):
        if not line.strip():
            blanks += 1
            continue
        try:
            event = load_json(line)
            if not isinstance(event, dict) or not {'event_id', 'source', 'fields'} <= set(event) or set(event) - {'event_id', 'source', 'fields', 'expected_match'}:
                raise ValidationError('Require event_id, source, fields, and optional expected_match only.')
            valid_string(event['event_id'], 'event_id', 80)
            if not isinstance(event['source'], dict) or set(event['source']) != {'product', 'category'}:
                raise ValidationError('source requires exactly product and category.')
            for value in event['source'].values():
                valid_string(value, 'source value', 80)
            fields = event['fields']
            if not isinstance(fields, dict) or not 1 <= len(fields) <= 64:
                raise ValidationError('fields must contain 1..64 flat scalar values.')
            for key, value in fields.items():
                if not FIELD.fullmatch(key) or type(value) not in (str, int, bool, type(None)):
                    raise ValidationError('Event fields must be named flat strings, integers, Booleans or null. Arrays/nested objects are unsupported.')
                if isinstance(value, str) and len(value) > 4096:
                    raise ValidationError('Event field strings are limited to 4096 characters.')
                if type(value) is int and abs(value) > 2**63 - 1:
                    raise ValidationError('Event integer exceeds signed 64-bit range.')
            if 'expected_match' in event and type(event['expected_match']) is not bool:
                raise ValidationError('expected_match must be a Boolean fixture expectation, not an attack label.')
            events.append((index, event))
        except ValidationError as exc:
            diagnostics.append({'line': index, 'reason': str(exc)})
    return events, diagnostics, blanks, len(lines)


class Budget:
    def __init__(self):
        self.work = 0

    def spend(self, amount):
        self.work += amount
        if self.work > MAX_WORK:
            raise ValidationError('Evaluation work limit reached. Reduce events, predicates or value-list lengths. No partial report returned.')


def match_field(fields, field, op, values, require_all, budget):
    present = field in fields
    if op == 'exists':
        budget.spend(1)
        return present == values[0]
    if not present or fields[field] is None:
        budget.spend(1)
        return False
    actual = fields[field]
    results = []
    for value in values:
        budget.spend(1 + (len(actual) if isinstance(actual, str) else 1) + (len(value) if isinstance(value, str) else 1))
        if type(value) is not type(actual):
            results.append(False)
        elif isinstance(value, str):
            left, right = actual.casefold(), value.casefold()
            results.append({'eq': lambda: left == right, 'contains': lambda: right in left,
                            'startswith': lambda: left.startswith(right), 'endswith': lambda: left.endswith(right)}[op]())
        else:
            results.append(actual == value)
    return all(results) if require_all else any(results)


def metrics(counts):
    tp, fp, fn, tn = (counts[key] for key in ('true_positive', 'false_positive', 'false_negative', 'true_negative'))
    return {'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'fixture_agreement': (tp + tn) / (tp + fp + fn + tn) if tp + fp + fn + tn else None}


def evaluate_rule(text, events, budget):
    rule, groups, condition = parse_rule(text)
    rows, missing, eligible, matched = [], {}, 0, 0
    counts = dict.fromkeys(('true_positive', 'false_positive', 'false_negative', 'true_negative', 'unlabeled'), 0)
    for line, event in events:
        source_matches = event['source'] == rule['logsource']
        selection_results, predicates = {}, []
        if source_matches:
            eligible += 1
            for name, fields in groups.items():
                field_results = []
                for field, op, values, require_all, key in fields:
                    if field not in event['fields']:
                        missing[field] = missing.get(field, 0) + 1
                    result = match_field(event['fields'], field, op, values, require_all, budget)
                    field_results.append(result)
                    predicates.append({'selection': name, 'predicate': key, 'present': field in event['fields'], 'matched': result})
                selection_results[name] = all(field_results)
            result = condition.matches(selection_results)
        else:
            result = False
        matched += result
        expected = event.get('expected_match')
        if expected is None:
            outcome = 'unlabeled'
        elif result and expected:
            outcome = 'true_positive'
        elif result:
            outcome = 'false_positive'
        elif expected:
            outcome = 'false_negative'
        else:
            outcome = 'true_negative'
        counts[outcome] += 1
        rows.append({'line': line, 'event_id': event['event_id'], 'source_matches': source_matches,
                     'matched': result, 'expected_match': expected, 'outcome': outcome,
                     'selections': selection_results, 'predicates': predicates})
    labeled = len(events) - counts['unlabeled']
    return {'rule': rule, 'rule_sha256': hashlib.sha256(text.encode()).hexdigest(), 'valid_events': len(events),
            'source_eligible': eligible, 'source_excluded': len(events) - eligible, 'matches': matched,
            'labeled_events': labeled, 'counts': counts, 'metrics': metrics(counts),
            'missing_field_predicates': missing, 'rows': rows}


LIMITS = [
    'DRW/1 local event matching only. No Sigma import, YAML parsing, backend conversion, SIEM deployment, live monitoring or external lookup.',
    'A match is rule behavior, not proof of malicious activity. A non-match does not establish safety.',
    'Expected-match labels are user-supplied fixture expectations. Precision/recall describe agreement with those labels, not real-world attack detection accuracy.',
    'Source product/category must match exactly. Source-excluded valid events count as non-matches, including in fixture metrics.',
    'Field names are literal and case-sensitive, including dots. String matching is Unicode casefolded; integers and Booleans are strictly typed. No field coercion or browser/SIEM equivalence is promised.',
    'Missing/null fields fail ordinary predicates; exists checks key presence including null. NOT can therefore allow an event with a missing filter field. Review coverage.',
    'No aggregation, time windows, correlations, regex, wildcards, nested event objects, field mapping or enrichment.',
    'Invalid records are excluded and reported. Duplicate event IDs/records are retained; line numbers identify occurrences.',
    'At most 200 event evidence rows, 50 diagnostics and 200 changed-match rows are shown/exported. Aggregate counts cover all valid input events.',
    'Reports contain full rule definitions, event IDs, line numbers and structural match evidence. Event field values are withheld, but rules and identifiers may contain sensitive information. Review before sharing.',
]


def run(candidate_text, event_text, baseline_text=None):
    # Validate all requested rules before parsing/evaluating events.
    parse_rule(candidate_text)
    if baseline_text is not None:
        parse_rule(baseline_text)
    events, diagnostics, blanks, physical = parse_events(event_text)
    budget = Budget()
    candidate = evaluate_rule(candidate_text, events, budget)
    baseline = evaluate_rule(baseline_text, events, budget) if baseline_text is not None else None
    changes = []
    if baseline:
        for old, new in zip(baseline['rows'], candidate['rows']):
            if old['matched'] != new['matched']:
                changes.append({'line': new['line'], 'event_id': new['event_id'], 'baseline_matched': old['matched'],
                                'candidate_matched': new['matched'], 'expected_match': new['expected_match']})
    for result in (candidate, baseline):
        if result:
            result['omitted_rows'] = max(0, len(result['rows']) - 200)
            result['rows'] = result['rows'][:200]
    status = 'no_valid_events' if not events else 'partial' if diagnostics else 'complete'
    return {'tool': 'Detection Rule Workbench', 'version': '0.1', 'report_id': str(uuid.uuid4()),
            'observed_at': datetime.now(timezone.utc).isoformat(), 'status': status,
            'input': {'physical_lines': physical, 'blank_lines': blanks, 'valid_events': len(events),
                      'invalid_records': len(diagnostics), 'events_sha256': hashlib.sha256(event_text.encode()).hexdigest()},
            'candidate': candidate, 'baseline': baseline, 'changed_match_count': len(changes), 'changed_matches': changes[:200],
            'omitted_changed_matches': max(0, len(changes) - 200), 'diagnostics': diagnostics[:50],
            'omitted_diagnostics': max(0, len(diagnostics) - 50), 'limits': LIMITS}


def to_csv(report):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    writer.writerow(['report_id', 'implementation', 'line', 'event_id', 'source_matches', 'matched', 'expected_match', 'fixture_outcome'])
    for name in ('baseline', 'candidate'):
        if report[name]:
            for row in report[name]['rows']:
                values = [report['report_id'], name, row['line'], row['event_id'], row['source_matches'],
                          row['matched'], '' if row['expected_match'] is None else row['expected_match'], row['outcome']]
                writer.writerow(["'" + str(v) if str(v).lstrip().startswith(('=', '+', '-', '@')) else v for v in values])
    return stream.getvalue()
