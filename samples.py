"""Synthetic fixtures. Text examples are inert and are never executed."""
import json


def rule(title, source, selections, condition, identifier='5a8cc9d8-2659-4ab4-b50d-a179bfc0f734'):
    return {'format': 'drw/1', 'id': identifier, 'title': title,
            'description': 'Synthetic training rule. Review matches in context; not proof of an incident.',
            'level': 'medium', 'logsource': source, 'selections': selections, 'condition': condition}


WINDOWS = {'product': 'windows', 'category': 'process_creation'}
AUTH = {'product': 'training', 'category': 'authentication'}
BROAD = rule('Encoded PowerShell flag — broad baseline', WINDOWS,
             {'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['-enc ', '-encodedcommand ']}}, 'selection')
TUNED = rule('Encoded PowerShell flag — tuned fixture', WINDOWS,
             {'selection': {'Image|endswith': ['\\powershell.exe', '\\pwsh.exe'], 'CommandLine|contains': ['-enc ', '-encodedcommand ']},
              'filter_automation': {'User': 'LAB\\automation'}}, 'selection and not filter_automation',
             'a6208b61-8c81-4ce1-8a73-e59bfd2a442f')


def event(identifier, image, command, user, expected):
    return {'event_id': identifier, 'source': WINDOWS,
            'fields': {'Image': image, 'CommandLine': command, 'User': user}, 'expected_match': expected}


PROCESS_EVENTS = [
    event('proc-001', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell.exe -EncodedCommand DEMO_PLACEHOLDER', 'LAB\\alice', True),
    event('proc-002', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell.exe -enc DEMO_PLACEHOLDER', 'LAB\\bob', True),
    event('proc-003', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell.exe -EncodedCommand DEMO_PLACEHOLDER', 'LAB\\automation', False),
    event('proc-004', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell.exe Get-Date', 'LAB\\alice', False),
    event('proc-005', 'C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c echo training', 'LAB\\alice', False),
    event('proc-006', 'C:\\Program Files\\PowerShell\\7\\pwsh.exe', 'pwsh.exe -EncodedCommand DEMO_PLACEHOLDER', 'LAB\\alice', True),
]
AUTH_RULE = rule('Failed authentication to a named admin account', AUTH,
                 {'failure': {'Result': 'failure'}, 'account': {'User|startswith': 'admin'}}, 'failure and account',
                 '17140487-c4cf-4bd8-8a02-133438ef9479')
AUTH_EVENTS = [
    {'event_id': 'auth-001', 'source': AUTH, 'fields': {'Result': 'failure', 'User': 'admin'}, 'expected_match': True},
    {'event_id': 'auth-002', 'source': AUTH, 'fields': {'Result': 'failure', 'User': 'admin.backup'}, 'expected_match': True},
    {'event_id': 'auth-003', 'source': AUTH, 'fields': {'Result': 'success', 'User': 'admin'}, 'expected_match': False},
    {'event_id': 'auth-004', 'source': AUTH, 'fields': {'Result': 'failure', 'User': 'alice'}, 'expected_match': False},
]


def dump(value):
    return json.dumps(value, indent=2, ensure_ascii=True)


def jsonl(events):
    return '\n'.join(json.dumps(e, ensure_ascii=True) for e in events) + '\n'


def get_sample(name):
    if name in ('broad', 'tuned'):
        return {'baseline': dump(BROAD), 'candidate': dump(BROAD if name == 'broad' else TUNED),
                'events': jsonl(PROCESS_EVENTS), 'compare': name == 'tuned'}
    if name == 'auth':
        return {'baseline': dump(AUTH_RULE), 'candidate': dump(AUTH_RULE), 'events': jsonl(AUTH_EVENTS), 'compare': False}
    if name == 'partial':
        wrong_source = {**PROCESS_EVENTS[0], 'event_id': 'source-excluded', 'source': AUTH}
        missing = {'event_id': 'missing-user', 'source': WINDOWS, 'fields': {'Image': 'C:\\powershell.exe', 'CommandLine': 'powershell.exe -enc DEMO'}, 'expected_match': True}
        return {'baseline': dump(BROAD), 'candidate': dump(TUNED), 'compare': False,
                'events': jsonl([PROCESS_EVENTS[0]]) + '{not valid JSON}\n' + json.dumps({'event_id': 'bad-shape', 'source': WINDOWS, 'fields': {'Image': ['unsupported']}}) + '\n' + jsonl([missing, wrong_source])}
    if name == 'invalid':
        invalid = rule('Unsupported regex example', WINDOWS, {'selection': {'CommandLine|re': '.*'}}, 'selection')
        return {'baseline': dump(BROAD), 'candidate': dump(invalid), 'events': jsonl(PROCESS_EVENTS), 'compare': False}
    raise KeyError(name)
