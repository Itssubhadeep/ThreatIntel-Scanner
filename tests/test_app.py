import hashlib
import io
from app import app, inspect_url


def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_home():
    assert client().get('/').status_code == 200


def test_url_flags():
    result = inspect_url('http://127.0.0.1/reset-password')
    assert result['score'] > 0
    assert 'Hostname is an IP address' in result['flags']


def test_reject_non_http_url():
    assert client().post('/api/url', json={'url': 'file:///etc/passwd'}).status_code == 400


def test_url_api():
    response = client().post('/api/url', json={'url': 'https://example.com'})
    assert response.status_code == 200
    assert response.json['hostname'] == 'example.com'


def test_file_hash():
    response = client().post('/api/hash', data={'file': (io.BytesIO(b'hello'), 'sample.txt')})
    assert response.status_code == 200
    assert response.json['sha256'] == hashlib.sha256(b'hello').hexdigest()


def test_missing_file():
    assert client().post('/api/hash').status_code == 400


def test_oversized_file():
    response = client().post('/api/hash', data={'file': (io.BytesIO(b'a' * (10 * 1024 * 1024 + 1)), 'big.bin')})
    assert response.status_code == 413


def test_no_vt_call_without_optin(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('VirusTotal must be opt-in')
    monkeypatch.setattr('app.vt_lookup', forbidden)
    assert client().post('/api/url', json={'url': 'https://example.com'}).status_code == 200
