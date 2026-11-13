import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

source = Path(__file__).resolve().parents[1] / 'worker.py'
loader = importlib.util.spec_from_file_location('local_worker', source)
worker = importlib.util.module_from_spec(loader)
loader.loader.exec_module(worker)


def record(country='JP', timezone='Asia/Tokyo'):
    return dict(success=True, ip='203.0.113.8', country_code=country, country='Test country',
                timezone={'id': timezone}, latitude=35.68, longitude=139.76, region='Test region', city='Test city')


def spec(kind='socks5'):
    return dict(proxyType=kind, proxyHost='127.0.0.1', proxyPort='18765',
                proxyUsername='qa-user', proxyPassword='p@ss:word', locale='ja-JP', timezone='Asia/Tokyo',
                canvasNoise=True, webgl=True, blockWebRTC=True)


class RegionTests(unittest.TestCase):
    def test_major_languages_and_actual_timezone(self):
        for country, timezone, language in [('JP','Asia/Tokyo','ja-JP'), ('US','America/New_York','en-US'),
                ('CN','Asia/Shanghai','zh-CN'), ('TW','Asia/Taipei','zh-Hant-TW'),
                ('SG','Asia/Singapore','en-SG'), ('DE','Europe/Berlin','de-DE')]:
            with self.subTest(country=country):
                result = worker.parse_region(record(country, timezone))
                self.assertEqual(result['locale'], language)
                self.assertEqual(result['timezone'], timezone)

    def test_missing_or_bad_data_is_rejected(self):
        bad = [dict(success=False), {**record(), 'timezone': {'id':'Invalid/Zone'}},
               {**record(), 'latitude':None}, {**record(), 'latitude':float('nan')},
               {**record(), 'ip':'not-an-ip'}, {**record(), 'country_code':'ZZ'}]
        for data in bad:
            with self.subTest(data=data):
                with self.assertRaises(ValueError): worker.parse_region(data)

    def test_proxy_is_explicit_no_shell_inheritance_and_escaped(self):
        with patch('requests.Session') as factory:
            session = factory.return_value.__enter__.return_value
            session.get.return_value.json.return_value = record()
            worker.detect_region(spec())
            self.assertFalse(session.trust_env)
            self.assertEqual(session.proxies['https'], 'socks5h://qa-user:p%40ss%3Aword@127.0.0.1:18765')
            self.assertEqual(session.get.call_count, 1)
            self.assertEqual(session.get.call_args.args[0], 'https://ipwho.is/')

    def test_proxy_failure_is_not_retried_or_disclosed(self):
        import requests
        with patch('requests.Session') as factory:
            session = factory.return_value.__enter__.return_value
            session.get.side_effect = requests.exceptions.ProxyError('secret p@ss:word')
            with self.assertRaises(RuntimeError) as error: worker.detect_region(spec())
            self.assertNotIn('p@ss:word', str(error.exception))
            self.assertEqual(session.get.call_count, 1)

    def test_region_overlay_preserves_base_identity(self):
        settings = {key: spec()[key] for key in ('locale','timezone','canvasNoise','webgl','blockWebRTC')}
        saved = dict(settings=settings, env={'CAMOU_CONFIG_1':json.dumps({'navigator.hardwareConcurrency':8,'timezone':'Asia/Tokyo'})},
                     prefs={'webgl.disabled':False}, args=[])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'identity.json'
            path.write_text(json.dumps(saved))
            original = path.read_bytes()
            current = spec(); current['resolvedRegion'] = worker.parse_region(record())
            with patch('camoufox.pkgman.launch_path',return_value='/engine'), patch('camoufox.utils.launch_options') as generate:
                options = worker.build_options(current, Path(directory))
            generate.assert_not_called()
            self.assertEqual(original,path.read_bytes())
            chunks = sorted((int(k.rsplit('_',1)[1]),v) for k,v in options['env'].items() if k.startswith('CAMOU_CONFIG_'))
            config = json.loads(''.join(v for _,v in chunks))
            self.assertEqual(config['geolocation:latitude'],35.68)
            self.assertEqual(config['navigator.hardwareConcurrency'],8)
            self.assertEqual(options['firefox_user_prefs']['permissions.default.geo'],1)
            self.assertNotIn('permissions.default.geo',saved['prefs'])


if __name__ == '__main__': unittest.main()
