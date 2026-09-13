'''Tachyon Networks device implementation.

Covers the whole TNA-30x/TNS-100 family (confirmed live: a TNA-301, a
TNA-302 and three TNA-303X units) - unlike Ubiquiti's fleet, every
Tachyon model confirmed so far speaks the exact same versioned REST
API, so there's no per-model class split here, just this one
TachyonDevice.

API: the officially documented RESTful API under /cgi.lua/apiv1/ (see
https://tachyon-networks.github.io/api_docs/ and
https://tachyon-networks.freshdesk.com/support/solutions/articles/67000659777),
not the older unversioned /cgi.lua/* surface some other tooling for
this hardware uses.

Auth:
- POST /cgi.lua/apiv1/login, JSON body {"username":..., "password":...}.
  Response: {"level":0,"token":"...","auth":true} (level 9 for a
  read-only account).
- IMPORTANT, confirmed live: the response also carries a `Set-Cookie`
  header of its own (named `token`), but that's NOT what the apiv1
  endpoints actually check - a request replaying that exact cookie
  gets 401 Unauthorized. What actually works, confirmed live and
  matching the docs' own curl example, is manually sending the login
  response's `token` field back as a cookie named `api_token` on every
  subsequent request. Don't rely on requests' automatic cookie-jar
  replay here - the cookie has to be built explicitly.
- No Origin/Referer header requirement observed (unlike a quirk
  confirmed on some Ubiquiti hardware) - plain requests work fine.
- Tokens expire after 30 minutes idle, or on a device reboot.

Confirmed endpoints:
- login (POST)                  - Described above.
- stats (GET, ?type=...)        - Comma-joinable: system, network,
                                   wireless, ethernet. `system` alone
                                   returns this device's identification
                                   (model/name/hostname/location/
                                   serial_no/fw_version) plus live
                                   health (cpu/memory/temp/uptime) -
                                   the main thing get_system_info()
                                   wraps. `network` returns per-zone
                                   VLAN/bridge/interface/IP data.
- config (GET)                  - Full device configuration. Not
                                   implemented here yet - config (POST)
                                   even less so, since this package is
                                   read-only for now (see
                                   change_password()/apply_changes()).
- reboot (POST), update (PUT)   - Confirmed to exist in the docs, not
                                   implemented - firmware/reboot actions
                                   are out of scope for a read-only
                                   identify/inventory package.

Sensitive data warning: config (not implemented here) is documented to
contain local user password hashes - if it's ever added, callers must
not log/print it wholesale.
'''
from __future__ import annotations

# System imports
import dataclasses
import logging

# External imports
import requests

# Local imports
from . import exceptions

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class TachyonSystemInfo:
    '''Structured view of stats(type="system") - this device's own
    identification and live health, exactly what's needed to name and
    provision it (mirrors the shape core.cpe's Ubiquiti pipeline
    expects: a model name plus enough identity to tell devices apart).
    '''
    name: str
    hostname: str
    model: str
    serial_no: str
    fw_version: str
    location: str
    uptime_seconds: int
    cpu_usage_percent: float | None
    cpu_temp_c: float | None


class TachyonDevice:
    '''Tachyon Networks device handler (TNA-301/302/303X, TNS-100).

    Read-only for now: change_password()/apply_changes() are
    deliberately no-ops, never touching the device.
    '''

    _default_user = 'root'
    _default_timeout = 30
    _verify_ssl = False

    def __init__(
        self, management_ip: str, timeout: int | None = None, use_ssl: bool = False,
    ) -> None:
        '''Constructor.

        Args:
            management_ip: Hostname or IP of the device.
            timeout: Per-request timeout in seconds. Defaults to 30.
            use_ssl: Use https instead of http. Defaults to False - every
                unit confirmed so far was managed over plain http, and
                the docs note the device's HTTPS listener uses a
                self-signed certificate.
        '''
        self._mgmt_ip = management_ip
        self._timeout = self._default_timeout if timeout is None else timeout
        self._use_ssl = use_ssl

        self._curr_username = None
        self._curr_password = None
        self._auth_token = None
        self._session = requests.Session()

    def _build_url(self, path: str) -> str:
        scheme = 'https' if self._use_ssl else 'http'
        return f"{scheme}://{self._mgmt_ip}/cgi.lua/apiv1/{path}"

    def _get(self, path: str, params: dict | None = None) -> requests.Response:
        '''Authenticated GET against a data endpoint.

        The api_token cookie is built explicitly rather than relying on
        the session's automatic cookie-jar replay - see the module
        docstring's Auth section for why that doesn't work here.
        '''
        return self._session.get(
            self._build_url(path),
            params=params,
            cookies={'api_token': self._auth_token},
            verify=self._verify_ssl,
            timeout=self._timeout,
        )

    def login(
        self, passwords: list[str], username: str | None = None, auto_apply: bool = False,
    ) -> None:
        '''Login to the device, trying `passwords` in order.

        Mirrors ubnt_automata's AirOSCommonDevice.login() -- on success
        with anything but passwords[0], change_password(passwords[0])
        is called (currently a no-op here, see its docstring) so a
        fleet converges on one shared password over time.
        '''
        self._curr_username = self._default_user if username is None else username

        try:
            primary_pw = passwords[0]
            self.login_http(curr_pw=primary_pw, curr_user=self._curr_username)
        except exceptions.WrongPassword as exc:
            logger.debug("Primary password failed, trying alternates")
            pw_found = False
            for curr_pw in passwords[1:]:
                try:
                    self.login_http(curr_pw=curr_pw, curr_user=self._curr_username)
                    self.change_password(primary_pw)
                    if auto_apply:
                        self.apply_changes()
                    pw_found = True
                    break
                except exceptions.WrongPassword:
                    pass

            if not pw_found:
                raise exceptions.WrongPassword(
                    f"Device {self._mgmt_ip} does not have a known password"
                ) from exc

    def login_http(self, curr_pw: str, curr_user: str | None = None) -> None:
        '''Login to device via HTTP(s).

        Raises:
            exceptions.WrongPassword: the login failed for authentication reasons.
            exceptions.DeviceUnavailable: the login failed for connectivity reasons.
        '''
        if curr_user is None:
            curr_user = self._default_user

        try:
            rez = self._session.post(
                self._build_url('login'),
                json={'username': curr_user, 'password': curr_pw},
                verify=self._verify_ssl,
                timeout=self._timeout,
            )
            auth_result = rez.json()
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.JSONDecodeError) as exc:
            raise exceptions.DeviceUnavailable from exc

        if not auth_result.get('auth'):
            raise exceptions.WrongPassword(f"Login to Tachyon device '{self._mgmt_ip}' failed")

        self._curr_username = curr_user
        self._curr_password = curr_pw
        self._auth_token = auth_result['token']

    def change_password(self, new_password: str) -> None:
        '''No-op for now - fetch-only, never modifies the device.'''
        logger.debug(
            f"change_password() called on {self._mgmt_ip} but is a no-op - not implemented yet"
        )

    def apply_changes(self, test_mode: bool = False) -> None:
        '''No-op for now - fetch-only, never modifies the device.'''
        logger.debug(
            f"apply_changes() called on {self._mgmt_ip} but is a no-op - not implemented yet"
        )

    def get_stats(self, stat_type: str = 'system') -> dict:
        '''Get raw stats (stats).

        Args:
            stat_type: One or more of "system", "network", "wireless",
                "ethernet", comma-joined for more than one in a single
                request (confirmed live) - e.g. "system,network".

        Raises:
            RuntimeError: the data can't be parsed.

        Returns:
            dict: One key per requested type, e.g. {"system": {...}}.
        '''
        res = self._get('stats', params={'type': stat_type})

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error fetching stats: {res.status_code} {res.text}")

    def get_system_info(self) -> TachyonSystemInfo:
        '''This device's own identification and live health
        (stats(type="system")).

        Raises:
            RuntimeError: the data can't be parsed.

        Returns:
            TachyonSystemInfo: Structured device identification.
        '''
        system = self.get_stats('system').get('system', {})

        return TachyonSystemInfo(
            name=system.get('name', ''),
            hostname=system.get('hostname', ''),
            model=system.get('model', ''),
            serial_no=system.get('serial_no', ''),
            fw_version=system.get('fw_version', ''),
            location=system.get('location', ''),
            uptime_seconds=system.get('uptime', 0),
            cpu_usage_percent=system.get('cpu_usage_percent'),
            cpu_temp_c=system.get('cpu_temp'),
        )
