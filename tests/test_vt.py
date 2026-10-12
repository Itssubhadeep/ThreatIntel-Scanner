from app import interpret_vt, vt_lookup, app

def test_detected():
    assert interpret_vt({'malicious': 2})[0] == 'DETECTED'

def test_suspicious():
    assert interpret_vt({'suspicious': 1})[0] == 'SUSPICIOUS'

def test_zero_detections_not_clean():
    assert interpret_vt({'malicious': 0, 'suspicious': 0})[0] == 'NO_DETECTIONS'

def test_no_key(monkeypatch):
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    assert vt_lookup('hash', 'a'*64)['verdict'] == 'NOT_SCANNED'

def test_vt_existing_report(monkeypatch):
    class Response:
        status_code=200
        def raise_for_status(self): pass
        def json(self):
            return {'data': {'attributes': {'last_analysis_stats': {'malicious': 3, 'undetected': 2},
                    'last_analysis_results': {'ExampleAV': {'category': 'malicious', 'result': 'Test.Detection'}}}}}
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake-test-key')
    monkeypatch.setattr('app.requests.get', lambda *args, **kwargs: Response())
    result=vt_lookup('hash','a'*64)
    assert result['verdict']=='DETECTED'
    assert result['stats']['malicious']==3
    assert result['engines'][0]['engine']=='ExampleAV'

def test_unknown_not_safe(monkeypatch):
    class Response: status_code=404
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake-test-key')
    monkeypatch.setattr('app.requests.get', lambda *args, **kwargs: Response())
    assert vt_lookup('hash','b'*64)['verdict']=='UNKNOWN'
