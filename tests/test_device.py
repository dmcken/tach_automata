'''Tests for TachyonDevice - covers the login response shape, the
api_token cookie quirk (the login response's own Set-Cookie header is
NOT what the API actually checks), and get_system_info()'s parsing.'''
import pytest
import requests

from tach_automata import exceptions
from tach_automata.device import TachyonDevice


class TestBuildUrl:
    def test_defaults_to_http(self):
        dev = TachyonDevice('192.0.2.1')
        assert dev._build_url('login') == 'http://192.0.2.1/cgi.lua/apiv1/login'

    def test_use_ssl_switches_scheme(self):
        dev = TachyonDevice('192.0.2.1', use_ssl=True)
        assert dev._build_url('login') == 'https://192.0.2.1/cgi.lua/apiv1/login'


class TestLoginHttp:
    def test_success_stores_auth_token(self, requests_mock):
        requests_mock.post(
            'http://192.0.2.1/cgi.lua/apiv1/login',
            json={'level': 0, 'token': 'fake-token-abc', 'auth': True},
        )
        dev = TachyonDevice('192.0.2.1')

        dev.login_http('correct-password', 'root')

        assert dev._auth_token == 'fake-token-abc'
        assert dev._curr_username == 'root'
        assert dev._curr_password == 'correct-password'

    def test_defaults_username_to_root(self, requests_mock):
        requests_mock.post(
            'http://192.0.2.1/cgi.lua/apiv1/login',
            json={'level': 0, 'token': 'fake-token', 'auth': True},
        )
        dev = TachyonDevice('192.0.2.1')

        dev.login_http('correct-password')

        sent = requests_mock.request_history[0].json()
        assert sent == {'username': 'root', 'password': 'correct-password'}

    def test_auth_false_is_wrong_password(self, requests_mock):
        requests_mock.post(
            'http://192.0.2.1/cgi.lua/apiv1/login',
            json={'auth': False},
        )
        dev = TachyonDevice('192.0.2.1')

        with pytest.raises(exceptions.WrongPassword):
            dev.login_http('wrong-password', 'root')

    def test_connection_error_is_device_unavailable(self, requests_mock):
        requests_mock.post(
            'http://192.0.2.1/cgi.lua/apiv1/login',
            exc=requests.exceptions.ConnectionError,
        )
        dev = TachyonDevice('192.0.2.1')

        with pytest.raises(exceptions.DeviceUnavailable):
            dev.login_http('correct-password', 'root')

    def test_non_json_response_is_device_unavailable(self, requests_mock):
        requests_mock.post(
            'http://192.0.2.1/cgi.lua/apiv1/login',
            text='<html>not json</html>',
        )
        dev = TachyonDevice('192.0.2.1')

        with pytest.raises(exceptions.DeviceUnavailable):
            dev.login_http('correct-password', 'root')


class TestLogin:
    def test_falls_back_to_alternate_password(self, requests_mock):
        requests_mock.post(
            'http://192.0.2.1/cgi.lua/apiv1/login',
            [
                {'json': {'auth': False}},
                {'json': {'level': 0, 'token': 'fake-token', 'auth': True}},
            ],
        )
        dev = TachyonDevice('192.0.2.1')

        dev.login(['wrong-password', 'correct-password'])

        assert dev._curr_password == 'correct-password'

    def test_no_known_password_raises_wrong_password(self, requests_mock):
        requests_mock.post(
            'http://192.0.2.1/cgi.lua/apiv1/login',
            json={'auth': False},
        )
        dev = TachyonDevice('192.0.2.1')

        with pytest.raises(exceptions.WrongPassword):
            dev.login(['wrong-1', 'wrong-2'])


class TestGet:
    def test_sends_api_token_as_a_cookie_not_a_header(self, requests_mock):
        '''Confirmed live: the login response's own Set-Cookie (named
        `token`) is not what the API actually checks - a request has
        to explicitly send the login response's `token` field back as
        a cookie named `api_token`. This locks that behaviour in.'''
        requests_mock.get(
            'http://192.0.2.1/cgi.lua/apiv1/stats',
            json={'system': {}},
        )
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token-abc'

        dev.get_stats()

        sent = requests_mock.request_history[0]
        assert sent.headers['Cookie'] == 'api_token=fake-token-abc'


class TestGetSystemInfo:
    def test_parses_identification_and_health_fields(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/cgi.lua/apiv1/stats',
            json={
                'system': {
                    'name': 'CON-TAP-E',
                    'hostname': 'CON-TAP-E',
                    'model': 'TNA-301',
                    'serial_no': 'TNA3011234500001',
                    'fw_version': '1.12.1 rev 54693',
                    'location': '',
                    'uptime': 39194876,
                    'cpu_usage_percent': 16,
                    'cpu_temp': 26.7,
                },
            },
        )
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token'

        info = dev.get_system_info()

        assert info.name == 'CON-TAP-E'
        assert info.model == 'TNA-301'
        assert info.serial_no == 'TNA3011234500001'
        assert info.uptime_seconds == 39194876
        assert info.cpu_temp_c == 26.7

    def test_missing_fields_default_sensibly(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/cgi.lua/apiv1/stats',
            json={'system': {}},
        )
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token'

        info = dev.get_system_info()

        assert info.name == ''
        assert info.uptime_seconds == 0
        assert info.cpu_usage_percent is None


class TestGetStats:
    def test_non_200_raises_runtime_error(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/cgi.lua/apiv1/stats',
            status_code=401,
            json={'error': {'details': 'Authorization Failed'}},
        )
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'stale-token'

        with pytest.raises(RuntimeError):
            dev.get_stats()


class TestGetInterfaces:
    def test_ap_idle_ethernet_bridge_and_radio(self, requests_mock, load_json):
        requests_mock.get(
            'http://192.0.2.1/cgi.lua/apiv1/stats',
            json=load_json('stats_ap_idle.json'),
        )
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token'

        interfaces = dev.get_interfaces()

        by_name = {i.name: i for i in interfaces}
        assert by_name['eth0'].kind == 'ethernet'
        assert by_name['eth0'].link_up is True
        assert by_name['eth1'].link_up is False
        assert by_name['br-wan'].kind == 'bridge'
        assert by_name['br-wan'].mac == '78:5E:E8:00:00:01'
        assert by_name['wlan0'].kind == 'wireless'
        assert by_name['wlan0'].mac == '78:5E:E8:00:00:03'


class TestGetIpaddresses:
    def test_ipv4_and_ipv6_from_bridge(self, requests_mock, load_json):
        requests_mock.get(
            'http://192.0.2.1/cgi.lua/apiv1/stats',
            json=load_json('stats_ap_idle.json'),
        )
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token'

        addresses = dev.get_ipaddresses()

        v4 = [a for a in addresses if a.version == 4]
        v6 = [a for a in addresses if a.version == 6]
        assert {a.address for a in v4} == {'169.254.1.1/16', '10.99.1.1/24'}
        assert all(a.gateway == '10.99.1.254' for a in v4)
        assert {a.address for a in v6} == {'fe80::7a5e:e8ff:fe00:1/64'}
        assert all(a.zone == 'wan' and a.interface == 'br-wan' for a in addresses)


class TestGetWireless:
    def test_idle_ap_radio_has_no_peers_despite_empty_dict_shape(self, requests_mock, load_json):
        '''Confirmed live: an idle radio's `peers` comes back as {}
        (a dict), not [] - this locks in that both shapes are handled.'''
        requests_mock.get(
            'http://192.0.2.1/cgi.lua/apiv1/stats',
            json=load_json('stats_ap_idle.json'),
        )
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token'

        radios = dev.get_wireless()

        assert len(radios) == 1
        assert radios[0].op_mode == 'master'
        assert radios[0].peers == []

    def test_connected_ptp_radio_has_one_peer(self, requests_mock, load_json):
        requests_mock.get(
            'http://192.0.2.1/cgi.lua/apiv1/stats',
            json=load_json('stats_ptp_connected.json'),
        )
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token'

        radios = dev.get_wireless()

        assert len(radios) == 1
        assert radios[0].op_mode == 'station'
        assert len(radios[0].peers) == 1
        peer = radios[0].peers[0]
        assert peer.mac == '78:5E:E8:00:00:03'
        assert peer.rssi == -47
        assert peer.distance_m == 111


class TestGetConfig:
    def test_returns_parsed_json(self, requests_mock):
        requests_mock.get(
            'http://192.0.2.1/cgi.lua/apiv1/config',
            json={'system': {'hostname': 'TEST'}},
        )
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token'

        assert dev.get_config() == {'system': {'hostname': 'TEST'}}


class TestSetConfig:
    def test_defaults_to_dry_run_true(self, requests_mock):
        requests_mock.post(
            'http://192.0.2.1/cgi.lua/apiv1/config',
            json={'valid': True},
        )
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token'

        dev.set_config({'system': {'hostname': 'TEST'}})

        assert requests_mock.request_history[0].qs['dry_run'] == ['true']

    def test_dry_run_false_is_sent_when_requested(self, requests_mock):
        requests_mock.post(
            'http://192.0.2.1/cgi.lua/apiv1/config',
            json={'valid': True},
        )
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token'

        dev.set_config({'system': {'hostname': 'TEST'}}, dry_run=False)

        assert requests_mock.request_history[0].qs['dry_run'] == ['false']

    def test_non_200_raises_runtime_error(self, requests_mock):
        requests_mock.post(
            'http://192.0.2.1/cgi.lua/apiv1/config',
            status_code=400,
            json={'error': 'invalid config'},
        )
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token'

        with pytest.raises(RuntimeError):
            dev.set_config({'system': {}})


class TestReboot:
    def test_success_returns_none(self, requests_mock):
        requests_mock.post('http://192.0.2.1/cgi.lua/apiv1/reboot', json={'status': 'ok'})
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token'

        assert dev.reboot() is None

    def test_non_200_raises_runtime_error(self, requests_mock):
        requests_mock.post('http://192.0.2.1/cgi.lua/apiv1/reboot', status_code=500)
        dev = TachyonDevice('192.0.2.1')
        dev._auth_token = 'fake-token'

        with pytest.raises(RuntimeError):
            dev.reboot()
