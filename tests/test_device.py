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
