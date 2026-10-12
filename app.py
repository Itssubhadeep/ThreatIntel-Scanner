import hashlib
import ipaddress
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024


def inspect_url(value):
    value = value.strip()
    if not value or len(value) > 2048:
        raise ValueError('Enter a URL under 2048 characters.')
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Enter a valid http:// or https:// URL without credentials.')
    host = parsed.hostname.lower()
    flags = []
    if parsed.scheme == 'http':
        flags.append('Connection is not HTTPS')
    if '@' in value:
        flags.append('URL contains @ symbol')
    if len(value) > 120:
        flags.append('Unusually long URL')
    if host.startswith('xn--') or '.xn--' in host:
        flags.append('Internationalized/punycode hostname')
    if host.count('.') >= 4:
        flags.append('Many hostname subdomains')
    try:
        ipaddress.ip_address(host)
        flags.append('Hostname is an IP address')
    except ValueError:
        pass
    if re.search(r'(?i)(verify|reset-password|account-update|urgent-login)', parsed.path):
        flags.append('Potentially sensitive action in URL path')
    return {'url': value, 'hostname': host, 'flags': flags, 'score': min(len(flags) * 20, 100),
            'note': 'Heuristic indicators only; not a malware verdict.'}


def sha256_stream(fileobj):
    digest = hashlib.sha256()
    while True:
        chunk = fileobj.read(65536)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def interpret_vt(stats):
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    if malicious:
        return 'DETECTED', 'One or more security engines flagged this indicator as malicious.'
    if suspicious:
        return 'SUSPICIOUS', 'One or more security engines marked this indicator suspicious.'
    return 'NO_DETECTIONS', 'No participating engines flagged this indicator in the available report. This does not prove safety.'


def vt_lookup(kind, indicator):
    """Retrieve an EXISTING VirusTotal report. No file bytes or URLs are submitted for analysis."""
    key = os.getenv('VIRUSTOTAL_API_KEY')
    if not key:
        return {'status': 'not_configured', 'verdict': 'NOT_SCANNED',
                'message': 'Set VIRUSTOTAL_API_KEY to request an existing VirusTotal report.'}
    if kind == 'url':
        import base64
        ident = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip('=')
        endpoint = f'https://www.virustotal.com/api/v3/urls/{ident}'
    else:
        endpoint = f'https://www.virustotal.com/api/v3/files/{indicator}'
    try:
        response = requests.get(endpoint, headers={'x-apikey': key}, timeout=12)
        if response.status_code == 404:
            return {'status': 'unknown', 'verdict': 'UNKNOWN',
                    'message': 'No existing VirusTotal report found. Not a clean verdict.'}
        if response.status_code in (401, 403, 429):
            return {'status': 'unavailable', 'verdict': 'NOT_SCANNED',
                    'message': f'VirusTotal returned HTTP {response.status_code}. Check API access or quota.'}
        response.raise_for_status()
        attributes = response.json().get('data', {}).get('attributes', {})
        raw = attributes.get('last_analysis_stats', {})
        categories = ('malicious', 'suspicious', 'harmless', 'undetected', 'timeout', 'failure', 'type-unsupported', 'confirmed-timeout')
        stats = {k: int(raw.get(k, 0)) for k in categories}
        verdict, explanation = interpret_vt(stats)
        engines = []
        for name, entry in attributes.get('last_analysis_results', {}).items():
            if not isinstance(entry, dict):
                continue
            engines.append({'engine': str(name), 'category': str(entry.get('category', 'undetected')),
                            'result': str(entry.get('result') or 'No detection')})
        engines.sort(key=lambda x: (x['category'] not in ('malicious', 'suspicious'), x['engine'].lower()))
        return {'status': 'found', 'verdict': verdict, 'message': explanation,
                'stats': stats, 'engines': engines[:150],
                'last_analysis_date': attributes.get('last_analysis_date'),
                'report_url': ('https://www.virustotal.com/gui/url/' if kind == 'url' else 'https://www.virustotal.com/gui/file/') +
                              (ident if kind == 'url' else indicator)}
    except (requests.RequestException, ValueError, TypeError, KeyError):
        return {'status': 'unavailable', 'verdict': 'NOT_SCANNED',
                'message': 'Reputation lookup failed. Check connection and try again.'}


@app.get('/')
def index():
    return render_template('index.html')


@app.post('/api/url')
def url_scan():
    data = request.get_json(silent=True) or {}
    try:
        result = inspect_url(str(data.get('url', '')))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    if data.get('reputation') is True:
        result['virustotal'] = vt_lookup('url', result['url'])
        result['verdict'] = result['virustotal']['verdict']
    result.setdefault('verdict', 'HEURISTIC_ONLY')
    result['timestamp'] = datetime.now(timezone.utc).isoformat()
    return jsonify(result)


@app.post('/api/hash')
def file_scan():
    uploaded = request.files.get('file')
    if not uploaded or not uploaded.filename:
        return jsonify({'error': 'Choose a file.'}), 400
    # Hash only: never save, open, or execute uploaded content.
    digest = sha256_stream(uploaded.stream)
    result = {'filename': os.path.basename(uploaded.filename.replace('\\', '/')),
              'sha256': digest, 'timestamp': datetime.now(timezone.utc).isoformat(),
              'note': 'File was hashed locally on this server; file bytes were not sent to VirusTotal.'}
    if request.form.get('reputation') == 'true':
        result['virustotal'] = vt_lookup('hash', digest)
        result['verdict'] = result['virustotal']['verdict']
    result.setdefault('verdict', 'HASH_ONLY')
    return jsonify(result)


@app.errorhandler(413)
def too_large(_):
    return jsonify({'error': 'Maximum upload size is 10 MB.'}), 413


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=False)
