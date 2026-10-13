"""MAC, Replay und dauerhafte Zustellung mit synthetischen Callback-Feldern."""

import hashlib
import hmac
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from greenbuddy2.webhook import Warteschlange, Eingang, pruefen, mac_berechnen, upstream_sender

SECRET = 'synthetisches-secret'


def callback(now=1000, message_id='test1', sender='ABSENDER_ID', receiver='GATEWAY_ID', secret=SECRET):
    row = {'from': sender, 'to': receiver, 'messageId': message_id, 'date': str(now), 'nonce': '00' * 24, 'box': 'ab' * 32}
    row['mac'] = mac_berechnen(row, secret)
    return urllib.parse.urlencode(row).encode()


class WebhookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'queue.sqlite3'
        self.queue = Warteschlange(self.path)
        self.addCleanup(self.queue.close)

    def test_mac_testvektor(self):
        fields = {'from': 'A', 'to': 'B', 'messageId': 'C', 'date': '1', 'nonce': 'D', 'box': 'E'}
        expected = hmac.new(b'synthetisches-secret', b'ABC1DE', hashlib.sha256).hexdigest()
        self.assertEqual(mac_berechnen(fields, SECRET), expected)
        self.assertEqual(pruefen(callback(), SECRET, 'GATEWAY_ID', 1000)['from'], 'ABSENDER_ID')

    def test_ungueltig_falsch_empfaenger_frische_flag(self):
        for body in (callback(secret='falsch'), callback(receiver='FALSCH'), callback() + b'&from=zweit', b'x' * 65537):
            with self.subTest(body=body[:10]), self.assertRaises(ValueError):
                pruefen(body, SECRET, 'GATEWAY_ID', 1000)
        self.assertEqual(pruefen(callback(now=100), SECRET, 'GATEWAY_ID', 1000)['date'], '100')
        for stamp in (99, 100, 1901):
            self.assertFalse(pruefen(callback(now=stamp), SECRET, 'GATEWAY_ID', 1000)['darf_wecken'])

    def test_replay_dedupe_persistent(self):
        secret_file = Path(self.tmp.name) / 'secret'
        secret_file.write_text(SECRET)
        secret_file.chmod(0o600)
        logger = mock.Mock()
        cfg = {'secret_file': str(secret_file), 'gateway_id': 'GATEWAY_ID', 'wake_sender': 'ABSENDER_ID'}
        incoming = Eingang(cfg, self.queue, logger, clock=lambda: 1000)
        self.assertEqual(incoming.annehmen(callback(), '198.51.100.9')[0], 200)
        status, row = incoming.annehmen(callback(), '198.51.100.9')
        self.assertEqual(status, 200)
        self.assertTrue(row['duplikat'])
        self.assertEqual(logger.emit.call_count, 1)
        self.assertEqual(logger.emit.call_args[0][0]['ereignis'], 'absender_freigegeben')
        self.assertEqual(len(self.queue.eintraege(1001)), 1)
        reopened = Warteschlange(self.path)
        try:
            self.assertEqual(reopened.annehmen('test1', callback(), 1001), (None, False))
        finally:
            reopened.close()

    def test_reihenfolge_quittung_und_ttl(self):
        for index in range(3):
            self.queue.annehmen('test%d' % index, b'verschluesselt', 1000 + index)
        sent = []
        def sender(entry_id, body, darf_wecken):
            sent.append(entry_id)
            return len(sent) == 1
        self.assertEqual(self.queue.zustellen(sender, 1010), 1)
        self.assertEqual(sent, [1, 2])
        self.assertEqual([r['id'] for r in self.queue.eintraege(1010)], [2, 3])
        self.queue.zustellen(lambda entry, body, darf_wecken: True, 1011)
        self.assertEqual(self.queue.metriken(1011)['zugestellt'], 3)
        self.assertEqual(self.queue.annehmen('test0', b'nochmal', 1012), (None, False))
        self.queue.annehmen('ablauf', b'probe', 1012)
        self.assertEqual(self.queue.bereinigen(1012 + 86400), 1)
        self.assertEqual(self.queue.metriken(100000)['abgelaufen'], 1)

    def test_queue_limits_503(self):
        queue = Warteschlange(Path(self.tmp.name) / 'klein.sqlite3', maximum=1, byte_limit=10)
        try:
            queue.annehmen('a', b'1234', 100)
            with self.assertRaises(OverflowError):
                queue.annehmen('b', b'1', 101)
            self.assertEqual(len(queue.eintraege(102)), 1)
        finally:
            queue.close()
        key = Path(self.tmp.name) / 'secret'
        key.write_text(SECRET)
        key.chmod(0o600)
        small = Warteschlange(Path(self.tmp.name) / 'voll.sqlite3', maximum=1)
        try:
            incoming = Eingang({'secret_file': str(key), 'gateway_id': 'GATEWAY_ID', 'wake_sender': 'ABSENDER_ID'},
                               small, mock.Mock(), clock=lambda: 1000)
            self.assertEqual(incoming.annehmen(callback(message_id='a'), '198.51.100.9')[0], 200)
            self.assertEqual(incoming.annehmen(callback(message_id='b'), '198.51.100.9')[0], 503)
        finally:
            small.close()

    def test_upstream_erfordert_quittung(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.headers = {'X-GreenBuddy-Quittung': '1'}
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch('greenbuddy2.webhook.urllib.request.build_opener', return_value=opener):
            send = upstream_sender('http://test.invalid/threema/incoming')
        self.assertTrue(send(1, b'verschluesselt'))
        response.headers = {}
        self.assertFalse(send(1, b'verschluesselt'))
        request = opener.open.call_args[0][0]
        self.assertEqual(request.get_header('X-greenbuddy-eingangs-id'), '1')
