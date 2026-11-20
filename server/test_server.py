"""Tests voor de ChainTrace-teamserver.  Draaien: python server/test_server.py"""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

TMP = tempfile.mkdtemp(prefix='ct-test-')
os.environ['CT_DATA'] = TMP
os.environ.pop('CT_ADMIN_USER', None)
os.environ.pop('CT_ADMIN_PASSWORD', None)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chaintrace_server as S  # noqa: E402

DOSSIER = {'tool': 'ChainTrace', 'version': 3, 'seed': {'chain': 'eth', 'addr': '0xabc'}, 'nodes': [], 'edges': []}


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = S.make_server(0)
        cls.base = 'http://127.0.0.1:%d' % cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(TMP, ignore_errors=True)

    def call(self, method, path, body=None, token=None, origin=None, expect=200):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            req.add_header('Content-Type', 'application/json')
        if token:
            req.add_header('Authorization', 'Bearer ' + token)
        if origin:
            req.add_header('Origin', origin)
        try:
            with urllib.request.urlopen(req) as r:
                status, raw, headers = r.status, r.read(), r.headers
        except urllib.error.HTTPError as e:
            status, raw, headers = e.code, e.read(), e.headers
        self.assertEqual(status, expect, raw[:300])
        try:
            return json.loads(raw), headers
        except Exception:
            return raw, headers

    def test_flow(self):
        info, _ = self.call('GET', '/api/info')
        self.assertTrue(info['setupNeeded'])
        self.call('POST', '/api/setup', {'code': 'WRONG', 'username': 'admin', 'password': 'geheim123'}, expect=403)
        adm, _ = self.call('POST', '/api/setup', {'code': S.SETUP_CODE, 'username': 'admin', 'password': 'geheim123'})
        A = adm['token']
        self.call('POST', '/api/setup', {'code': 'X', 'username': 'b', 'password': 'geheim123'}, expect=409)
        self.assertFalse(self.call('GET', '/api/info')[0]['setupNeeded'])

        # gebruikers
        self.call('POST', '/api/users', {'username': 'bob', 'password': 'wachtwoord1'}, token=A)
        self.call('POST', '/api/users', {'username': 'carol', 'password': 'wachtwoord2'}, token=A)
        self.call('POST', '/api/users', {'username': 'bob', 'password': 'wachtwoord1'}, token=A, expect=409)
        self.call('POST', '/api/users', {'username': 'x', 'password': 'kort'}, token=A, expect=400)
        self.call('POST', '/api/login', {'username': 'bob', 'password': 'fout'}, expect=401)
        B = self.call('POST', '/api/login', {'username': 'bob', 'password': 'wachtwoord1'})[0]['token']
        C = self.call('POST', '/api/login', {'username': 'carol', 'password': 'wachtwoord2'})[0]['token']
        self.call('POST', '/api/users', {'username': 'eve', 'password': 'wachtwoord3'}, token=B, expect=403)
        self.call('GET', '/api/cases', expect=401)

        # zaak + onderzoek
        case = self.call('POST', '/api/cases', {'name': 'Zaak Alfa'}, token=A)[0]['case']
        cid = case['id']
        self.assertEqual(case['role'], 'owner')
        self.call('PUT', '/api/cases/%s/items/eth:0xabc' % cid, {'meta': {'chain': 'eth', 'addr': '0xabc', 'title': 'Slachtoffer'}, 'dossier': DOSSIER}, token=A)
        self.call('PUT', '/api/cases/%s/items/x' % cid, {'dossier': {'tool': 'Other'}}, token=A, expect=400)
        self.call('GET', '/api/cases/%s' % cid, token=B, expect=403)

        # leden
        self.call('POST', '/api/cases/%s/members' % cid, {'username': 'bob', 'role': 'view'}, token=A)
        got = self.call('GET', '/api/cases/%s/items/eth:0xabc' % cid, token=B)[0]
        self.assertEqual(got['dossier']['seed']['addr'], '0xabc')
        self.call('PUT', '/api/cases/%s/items/eth:0xdef' % cid, {'dossier': DOSSIER}, token=B, expect=403)
        self.call('POST', '/api/cases/%s/members' % cid, {'username': 'carol'}, token=B, expect=403)
        self.call('POST', '/api/cases/%s/members' % cid, {'username': 'bob', 'role': 'edit'}, token=A)
        self.call('PUT', '/api/cases/%s/items/eth:0xdef' % cid, {'meta': {'title': 'Dader'}, 'dossier': DOSSIER}, token=B)
        # gelijktijdig bewerken: verouderde basis geeft 409
        cur = self.call('GET', '/api/cases/%s/items/eth:0xdef' % cid, token=A)[0]
        self.assertEqual(cur['updatedBy'], 'bob')
        self.call('PUT', '/api/cases/%s/items/eth:0xdef' % cid, {'base': cur['updated'] - 1, 'dossier': DOSSIER}, token=A, expect=409)
        up = self.call('PUT', '/api/cases/%s/items/eth:0xdef' % cid, {'base': cur['updated'], 'meta': {'title': 'Dader'}, 'dossier': DOSSIER}, token=A)[0]
        self.assertGreater(up['updated'], cur['updated'])
        self.call('PUT', '/api/cases/%s/items/eth:0xdef' % cid, {'base': up['updated'], 'meta': {'title': 'Dader'}, 'dossier': DOSSIER}, token=B)
        items = self.call('GET', '/api/cases/%s' % cid, token=A)[0]['case']['items']
        self.assertEqual({i['seedKey'] for i in items}, {'eth:0xabc', 'eth:0xdef'})
        self.assertEqual([i for i in items if i['seedKey'] == 'eth:0xdef'][0]['updatedBy'], 'bob')

        # opmerkingen en activiteit
        self.call('POST', '/api/cases/%s/comments' % cid, {'text': 'Binance-brief verstuurd'}, token=B)
        com = self.call('GET', '/api/cases/%s/comments' % cid, token=A)[0]['comments']
        self.assertEqual(com[0]['by'], 'bob')
        act = self.call('GET', '/api/cases/%s/activity' % cid, token=A)[0]['activity']
        self.assertTrue(any(a['action'] == 'comment' for a in act))

        # deellinks
        lv = self.call('POST', '/api/cases/%s/links' % cid, {'role': 'view'}, token=A)[0]['token']
        le = self.call('POST', '/api/cases/%s/links' % cid, {'role': 'edit'}, token=A)[0]['token']
        self.call('POST', '/api/cases/%s/links' % cid, {'role': 'edit'}, token=B, expect=403)
        sh = self.call('GET', '/api/shared/' + lv)[0]
        self.assertEqual(sh['case']['name'], 'Zaak Alfa')
        self.assertEqual(sh['case']['members'], [])
        self.assertEqual(self.call('GET', '/api/shared/%s/items/eth:0xabc' % lv)[0]['dossier']['tool'], 'ChainTrace')
        self.call('POST', '/api/join', {'token': le}, token=C)
        self.assertEqual(self.call('GET', '/api/cases/%s' % cid, token=C)[0]['case']['role'], 'edit')
        links = self.call('GET', '/api/cases/%s/links' % cid, token=A)[0]['links']
        vid = [l for l in links if l['role'] == 'view'][0]['id']
        self.call('DELETE', '/api/cases/%s/links/%s' % (cid, vid), token=A)
        self.call('GET', '/api/shared/' + lv, expect=404)

        # wijzigingen sinds
        ch = self.call('GET', '/api/changes?since=0', token=C)[0]
        self.assertIn(cid, [c['id'] for c in ch['cases']])
        self.assertEqual(self.call('GET', '/api/changes?since=%d' % (ch['now'] + 1000), token=C)[0]['cases'], [])

        # teamlabels
        self.call('PUT', '/api/labels', {'chain': 'eth', 'address': '0xdef', 'label': 'Dader A'}, token=B)
        lab = self.call('GET', '/api/labels', token=C)[0]['labels']
        self.assertEqual(lab[0]['label'], 'Dader A')
        self.call('PUT', '/api/labels', {'chain': 'eth', 'address': '0xdef', 'label': ''}, token=B)
        self.assertEqual(self.call('GET', '/api/labels', token=C)[0]['labels'], [])

        # verwijderen
        self.call('DELETE', '/api/cases/%s' % cid, token=B, expect=403)
        self.call('DELETE', '/api/cases/%s/members/carol' % cid, token=A)
        self.call('GET', '/api/cases/%s' % cid, token=C, expect=403)
        self.call('DELETE', '/api/cases/%s' % cid, token=A)
        self.call('GET', '/api/cases/%s' % cid, token=A, expect=404)

        # wachtwoord wijzigen maakt oude sessies ongeldig
        nb = self.call('POST', '/api/me/password', {'old': 'wachtwoord1', 'new': 'nieuwwachtwoord'}, token=B)[0]['token']
        self.call('GET', '/api/me', token=B, expect=401)
        self.assertEqual(self.call('GET', '/api/me', token=nb)[0]['username'], 'bob')
        self.call('POST', '/api/logout', token=nb)
        self.call('GET', '/api/me', token=nb, expect=401)

    def test_static_and_cors(self):
        body, h = self.call('GET', '/')
        self.assertIn(b'ChainTrace', body)
        self.assertEqual(h['X-Content-Type-Options'], 'nosniff')
        self.call('GET', '/../server/chaintrace_server.py', expect=404)
        self.call('GET', '/%2e%2e/server/chaintrace_server.py', expect=404)
        _, h = self.call('GET', '/api/info', origin='https://appassets.androidplatform.net')
        self.assertEqual(h['Access-Control-Allow-Origin'], 'https://appassets.androidplatform.net')
        _, h = self.call('GET', '/api/info', origin='https://evil.example')
        self.assertIsNone(h.get('Access-Control-Allow-Origin'))

    def test_bruteforce(self):
        for _ in range(6):
            self.call('POST', '/api/login', {'username': 'nobody', 'password': 'x'}, expect=401 if _ < 5 else 429)


if __name__ == '__main__':
    unittest.main(verbosity=2)
