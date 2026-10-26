import csv
import io
import json
import unittest
from unittest.mock import patch
from engine import Budget, Condition, ValidationError, evaluate_rule, load_json, match_field, parse_events, parse_rule, run, to_csv
from samples import AUTH_RULE, BROAD, PROCESS_EVENTS, TUNED, WINDOWS, dump, get_sample, jsonl, rule


class EngineTests(unittest.TestCase):
    def single(self, fields, selections, condition='selection', expected=None):
        candidate = rule('Test rule', WINDOWS, selections, condition)
        event = {'event_id': 'one', 'source': WINDOWS, 'fields': fields}
        if expected is not None:
            event['expected_match'] = expected
        return run(dump(candidate), jsonl([event]))['candidate']

    def test_broad_fixture_expected_mismatches(self):
        s = get_sample('broad')
        r = run(s['candidate'], s['events'])
        self.assertEqual(r['candidate']['matches'], 3)
        self.assertEqual(r['candidate']['counts'], {'true_positive': 2, 'false_positive': 1, 'false_negative': 1, 'true_negative': 2, 'unlabeled': 0})
        self.assertAlmostEqual(r['candidate']['metrics']['precision'], 2 / 3)

    def test_tuning_changes_false_positive_and_miss(self):
        s = get_sample('tuned')
        r = run(s['candidate'], s['events'], s['baseline'])
        self.assertEqual(r['changed_match_count'], 2)
        self.assertEqual([row['event_id'] for row in r['changed_matches']], ['proc-003', 'proc-006'])
        self.assertEqual(r['candidate']['counts']['true_positive'], 3)
        self.assertEqual(r['candidate']['counts']['true_negative'], 3)
        self.assertEqual(r['candidate']['metrics']['recall'], 1)
        self.assertEqual(r['baseline']['matches'], r['candidate']['matches'])

    def test_auth_fixture(self):
        s = get_sample('auth')
        self.assertEqual(run(s['candidate'], s['events'])['candidate']['matches'], 2)

    def test_condition_precedence_and_parentheses(self):
        values = {'a': True, 'b': False, 'c': False}
        self.assertTrue(Condition('a or b and c', values).matches(values))
        self.assertFalse(Condition('(a or b) and c', values).matches(values))
        self.assertTrue(Condition('a and not b and not c', values).matches(values))

    def test_condition_rejects_unknown_code_and_quantifiers(self):
        for text in ['__import__(x)', '1 of selection*', 'a xor b', 'a && b', 'a AND b', 'a)', '(a', '', 'not', 'a b']:
            with self.subTest(text=text), self.assertRaises(ValidationError):
                Condition(text, {'a', 'b'})

    def test_nesting_limit(self):
        with self.assertRaises(ValidationError):
            Condition('not ' * 18 + 'a', {'a'})

    def test_unused_selection_rejected(self):
        with self.assertRaises(ValidationError):
            Condition('a', {'a', 'b'})

    def test_fields_anded_and_lists_ored(self):
        result = self.single({'A': 'yes', 'B': 'no'}, {'selection': {'A': ['wrong', 'yes'], 'B': 'yes'}})
        self.assertEqual(result['matches'], 0)
        self.assertEqual(result['rows'][0]['predicates'][0]['matched'], True)

    def test_all_modifier_and_casefold(self):
        self.assertEqual(self.single({'Text': 'ABC def'}, {'selection': {'Text|contains|all': ['abc', 'DEF']}})['matches'], 1)
        self.assertEqual(self.single({'Text': 'abc'}, {'selection': {'Text|contains|all': ['abc', 'def']}})['matches'], 0)

    def test_operators(self):
        for operator in ('eq', 'contains', 'startswith', 'endswith'):
            with self.subTest(op=operator):
                self.assertTrue(match_field({'Text': 'TeSt'}, 'Text', operator, ['test'], False, Budget()))

    def test_strict_numeric_boolean_types(self):
        for actual in ('4625', True):
            self.assertFalse(match_field({'E': actual}, 'E', 'eq', [4625 if isinstance(actual, str) else 1], False, Budget()))
        self.assertTrue(match_field({'E': 4625}, 'E', 'eq', [4625], False, Budget()))

    def test_missing_and_null_vs_exists(self):
        for fields in ({}, {'E': None}):
            self.assertFalse(match_field(fields, 'E', 'eq', ['x'], False, Budget()))
        self.assertTrue(match_field({'E': None}, 'E', 'exists', [True], False, Budget()))
        self.assertTrue(match_field({}, 'E', 'exists', [False], False, Budget()))

    def test_field_names_case_sensitive_and_dots_literal(self):
        self.assertEqual(self.single({'A.b': 'yes'}, {'selection': {'A.b': 'yes'}})['matches'], 1)
        self.assertEqual(self.single({'a.b': 'yes'}, {'selection': {'A.b': 'yes'}})['matches'], 0)

    def test_missing_negative_filter_is_explicit(self):
        s = get_sample('partial')
        r = run(s['candidate'], s['events'])
        row = next(x for x in r['candidate']['rows'] if x['event_id'] == 'missing-user')
        self.assertTrue(row['matched'])
        self.assertFalse(row['selections']['filter_automation'])
        self.assertEqual(r['candidate']['missing_field_predicates']['User'], 1)

    def test_source_excluded_counted_as_nonmatch(self):
        e = {**PROCESS_EVENTS[0], 'source': {'product': 'Windows', 'category': 'process_creation'}}
        r = run(dump(BROAD), jsonl([e]))['candidate']
        self.assertEqual(r['source_excluded'], 1)
        self.assertEqual(r['counts']['false_negative'], 1)
        self.assertEqual(r['rows'][0]['predicates'], [])

    def test_unlabeled_metrics_not_fabricated(self):
        r = self.single({'X': 'yes'}, {'selection': {'X': 'yes'}})
        self.assertEqual(r['counts']['unlabeled'], 1)
        self.assertEqual(r['labeled_events'], 0)
        self.assertIsNone(r['metrics']['precision'])

    def test_zero_denominator_metric(self):
        r = self.single({'X': 'no'}, {'selection': {'X': 'yes'}}, expected=False)
        self.assertIsNone(r['metrics']['precision'])
        self.assertIsNone(r['metrics']['recall'])
        self.assertEqual(r['metrics']['fixture_agreement'], 1)

    def test_invalid_rule_modifiers_and_value_types(self):
        for key, value in [('X|re', 'x'), ('X|contains', 2), ('X|exists', [True]), ('X|contains|all', 'x'), ('X', []), ('X', None), ('X', '*glob*'), ('X|contains|eq', 'x'), ('X|eq|eq', 'x')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValidationError):
                parse_rule(dump(rule('Bad', WINDOWS, {'selection': {key: value}}, 'selection')))

    def test_duplicate_keys_and_nonfinite_numbers_rejected(self):
        for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            with self.assertRaises(ValidationError):
                load_json(text)

    def test_event_validation_diagnostics(self):
        s = get_sample('partial')
        r = run(s['candidate'], s['events'])
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['input']['valid_events'], 3)
        self.assertEqual(r['input']['invalid_records'], 2)
        self.assertEqual([d['line'] for d in r['diagnostics']], [2, 3])

    def test_invalid_labels_excluded(self):
        e = {**PROCESS_EVENTS[0], 'expected_match': 'true'}
        self.assertEqual(len(parse_events(jsonl([e]))[1]), 1)

    def test_empty_and_invalid_only_distinct(self):
        for text in ('', '{}\n'):
            r = run(dump(BROAD), text)
            self.assertEqual(r['status'], 'no_valid_events')
            self.assertIsNone(r['candidate']['metrics']['precision'])

    def test_duplicate_events_retained_line_refs(self):
        r = run(dump(BROAD), jsonl([PROCESS_EVENTS[0]] * 2))
        self.assertEqual(r['candidate']['matches'], 2)
        self.assertEqual([row['line'] for row in r['candidate']['rows']], [1, 2])

    def test_preview_and_diagnostic_caps_aggregate_counts_preserved(self):
        r = run(dump(BROAD), jsonl([PROCESS_EVENTS[0]] * 220) + '{}\n' * 60)
        self.assertEqual(r['candidate']['matches'], 220)
        self.assertEqual(len(r['candidate']['rows']), 200)
        self.assertEqual(r['candidate']['omitted_rows'], 20)
        self.assertEqual(r['input']['invalid_records'], 60)
        self.assertEqual(r['omitted_diagnostics'], 10)

    def test_changed_caps(self):
        r = run(dump(TUNED), jsonl([PROCESS_EVENTS[5]] * 220), dump(BROAD))
        self.assertEqual(r['changed_match_count'], 220)
        self.assertEqual(len(r['changed_matches']), 200)
        self.assertEqual(r['omitted_changed_matches'], 20)

    def test_line_byte_and_work_limits(self):
        for events in ('\n' * 1001, 'x' * (1024 * 1024 + 1)):
            with self.assertRaises(ValidationError):
                parse_events(events)
        with patch('engine.MAX_WORK', 1), self.assertRaises(ValidationError):
            run(dump(BROAD), jsonl(PROCESS_EVENTS))

    def test_rule_size_and_unicode_validation(self):
        for text in ('x' * 32769, '\ud800'):
            with self.assertRaises(ValidationError):
                parse_rule(text)

    def test_report_withholds_event_field_values(self):
        e = {**PROCESS_EVENTS[0], 'fields': {**PROCESS_EVENTS[0]['fields'], 'Secret': 'DO_NOT_EXPORT_8302'}}
        r = run(dump(BROAD), jsonl([e]))
        self.assertNotIn('DO_NOT_EXPORT_8302', json.dumps(r))
        self.assertNotIn('DEMO_PLACEHOLDER', json.dumps(r))

    def test_csv_formula_guard_and_caps(self):
        e = {**PROCESS_EVENTS[0], 'event_id': '=DANGEROUS_FORMULA'}
        r = run(dump(BROAD), jsonl([e]))
        rows = list(csv.reader(io.StringIO(to_csv(r))))
        self.assertEqual(rows[1][3], "'=DANGEROUS_FORMULA")

    def test_input_hash_changes(self):
        r1 = run(dump(BROAD), jsonl(PROCESS_EVENTS))
        r2 = run(dump(BROAD), '\n' + jsonl(PROCESS_EVENTS))
        self.assertNotEqual(r1['input']['events_sha256'], r2['input']['events_sha256'])

    def test_no_network_or_subprocess(self):
        with patch('socket.socket', side_effect=AssertionError('Network forbidden')), patch('subprocess.Popen', side_effect=AssertionError('Execution forbidden')):
            s = get_sample('tuned')
            self.assertEqual(run(s['candidate'], s['events'], s['baseline'])['candidate']['matches'], 3)


if __name__ == '__main__':
    unittest.main()
