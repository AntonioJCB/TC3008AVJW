"""Load local plugins in the installed SpiderFoot runtime, in memory, with mocked HTTP.
Run from repository root: python backend/tests/check_spiderfoot_runtime.py
No container rebuild, file mutation, scan scheduling, network or database access.
"""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
sources = {"baxter_passive": (root / "backend/app/spiderfoot_passive.py").read_text(encoding="utf-8")}
sources.update({p.stem: p.read_text(encoding="utf-8") for p in (root / "deploy/spiderfoot/modules").glob("sfp_baxter_*.py")})
script = "sources = " + repr(sources) + "\n" + r'''
import json, sys, types, hashlib
from unittest.mock import patch
from spiderfoot import SpiderFootEvent, SpiderFootTarget
loaded = {}
for name, source in sources.items():
    module = types.ModuleType(name)
    sys.modules[name] = module
    exec(compile(source, name + '.py', 'exec'), module.__dict__)
    loaded[name] = module
results = []
for provider, target, options, response in [
    ('urlscan', 'api.example.com', {}, {'results': [{'page': {'domain': 'api.example.com', 'server': 'FixtureServer/1.0'}, 'task': {'time': '2026-11-01T00:00:00Z'}}]}),
    ('internetdb', '8.8.8.8', {'use': 'noncommercial'}, {'ip': '8.8.8.8', 'ports': [22], 'cpes': ['cpe:/a:fixture:product:1.0'], 'vulns': ['CVE-2024-12345']}),
]:
    name = 'sfp_baxter_' + provider
    plugin = getattr(loaded[name], name)()
    meta = plugin.asdict()
    assert meta['cats'] == ['Search Engines']
    target_type = 'INTERNET_NAME' if provider == 'urlscan' else 'IP_ADDRESS'
    plugin.__name__ = name
    plugin.setup(None, options)
    plugin.setTarget(SpiderFootTarget(target, target_type))
    emitted = []
    plugin.notifyListeners = emitted.append
    root_event = SpiderFootEvent('ROOT', target, '', None)
    event = SpiderFootEvent(target_type, target, 'SpiderFoot UI', root_event)
    foreign = SpiderFootEvent(target_type, 'other.example.net' if provider == 'urlscan' else '9.9.9.9', 'fixture', root_event)
    with patch('requests.get', return_value=types.SimpleNamespace(status_code=200, json=lambda: response)) as request:
        plugin.handleEvent(foreign)
        request.assert_not_called()
        plugin.handleEvent(event)
        plugin.handleEvent(event)
        request.assert_called_once()
        assert request.call_args.kwargs['allow_redirects'] is False
    assert len(emitted) == 1
    report = json.loads(emitted[0].data)
    assert report['status'] == 'ok'
    assert 'fixture-key' not in emitted[0].data
    exported = {'event_type': emitted[0].eventType, 'data': emitted[0].data, 'module': name, 'scan_target': target, 'source_data': target, 'false_positive': 0}
    assert len(loaded['baxter_passive'].reports([exported])) == 1
    results.append({'module': name, 'status': 'passed', 'events': len(report['events']), 'real_spiderfoot_event': True})
print(json.dumps({'network': 'mocked', 'database': 'not accessed', 'runtime': results, 'sha256': {name: hashlib.sha256(source.encode()).hexdigest() for name, source in sources.items()}}, indent=2))
'''
result = subprocess.run(["docker", "compose", "exec", "-T", "spiderfoot", "python", "-"], input=script.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root)
if result.returncode:
    raise SystemExit(result.stderr.decode(errors="replace"))
text = result.stdout.decode()
json.loads(text)
(root / "docs/backend/spiderfoot-runtime-20261118.json").write_text(text, encoding="utf-8")
print(text)
