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
                                   VLAN/bridge/interface/IP data,
                                   `ethernet` per-port link/counters,
                                   `wireless` radios and connected
                                   peers - get_interfaces()/
                                   get_ipaddresses()/get_wireless() wrap
                                   these. Confirmed live against a
                                   TNA-302 acting as a PtMP AP (radio
                                   op_mode "master", `wireless.peers` an
                                   empty *dict* while nobody's
                                   connected) and a TNA-303X acting as
                                   one end of a PtP link (op_mode
                                   "station", `wireless.peers` a
                                   non-empty *list* once connected) -
                                   both shapes are handled.
- config (GET/POST)             - Full device configuration; POST
                                   supports a `dry_run` query param to
                                   validate without applying. Since
                                   this touches the live device,
                                   get_config() is implemented but
                                   set_config() defaults to dry_run=True
                                   - callers have to opt in explicitly
                                   with dry_run=False to actually change
                                   anything.
- reboot (POST)                 - Implemented, but never called
                                   automatically by anything in this
                                   package (including login()'s retry
                                   path) - a caller has to invoke it
                                   deliberately.
- update (PUT)                  - Firmware update. Not implemented -
                                   out of scope for now (needs its own
                                   care around picking/validating a
                                   firmware URL that this package has
                                   no way to verify).

Sensitive data warning: get_config()'s response is documented to
contain local user password hashes - callers must not log/print it
wholesale.
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

# Confirmed live on a TNA-303X: system.users[].password_hash (md5-crypt),
# wireless.radios.<radio>.passphrase, services.snmp.v2.community.
SECRET_KEY_NAMES = frozenset({
    'community', 'key', 'passphrase', 'password', 'password_hash', 'psk', 'secret',
})
REDACTED = '<redacted>'


def redact_secrets(config):
    '''Copy of `config` with secret values replaced by REDACTED.
    Empty values are left empty so "unset" stays distinguishable.'''
    if isinstance(config, list):
        return [redact_secrets(v) for v in config]
    if not isinstance(config, dict):
        return config
    result = {}
    for key, value in config.items():
        is_secret = str(key).lower() in SECRET_KEY_NAMES
        if is_secret and not isinstance(value, (dict, list)) and value not in ('', None):
            result[key] = REDACTED
        else:
            result[key] = redact_secrets(value)
    return result


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


@dataclasses.dataclass
class TachyonInterface:
    '''One physical (ethernet), bridge, or radio interface.

    `kind` is "ethernet", "bridge", or "wireless" -- ethernet ports and
    the radio come from a flat name->dict map (ethernet.ports,
    wireless.radios), the bridge from one entry per zone
    (network.zones.<zone>.data_bridge), so this normalizes all three
    into one shape rather than making callers know where each field
    actually lives.
    '''
    name: str
    kind: str
    mac: str
    link_up: bool | None
    speed_mbps: int | None
    duplex: str | None


@dataclasses.dataclass
class TachyonIPAddress:
    '''One IP address (v4 or v6) on a bridge interface, from
    network.zones.<zone>.data_bridge.
    '''
    zone: str
    interface: str
    address: str  # CIDR, e.g. "10.14.1.30/24"
    version: int
    gateway: str | None


@dataclasses.dataclass
class TachyonWirelessPeer:
    '''One connected peer on a radio - the far end of a PtP link, or
    one of possibly several clients on a PtMP AP.
    '''
    mac: str
    rssi: int | None
    remote_rssi: int | None
    snr: int | None
    tx_mcs: int | None
    rx_mcs: int | None
    distance_m: int | None
    connection_time_seconds: int | None


@dataclasses.dataclass
class TachyonWirelessRadio:
    '''One radio, e.g. wlan0.'''
    name: str
    mac: str
    op_mode: str  # "master" (AP/PtP-fixed-end) or "station" (PtP/PtMP client end)
    ssid: str
    freq_mhz: int | None
    channel: int | None
    channel_width_mhz: int | None
    security: str
    peers: list[TachyonWirelessPeer]


class TachyonDevice:
    '''Tachyon Networks device handler (TNA-301/302/303X, TNS-100).

    Identification and inventory (get_system_info/get_interfaces/
    get_ipaddresses/get_wireless) are read-only and safe to call
    freely. get_config()/set_config()/reboot() are real, working calls
    against the live device -- set_config() defaults to dry_run=True
    so it never applies anything unless a caller explicitly opts in,
    but reboot() has no such guard, since the API itself doesn't offer
    one. change_password()/apply_changes() are still deliberate no-ops:
    the config schema's user/password fields haven't been confirmed
    live yet, and guessing at field names for a write call against
    real hardware is exactly the kind of mistake this package's
    "confirmed live" discipline exists to avoid.
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

    def get_interfaces(self) -> list[TachyonInterface]:
        '''Every ethernet port, bridge, and radio as one flat list
        (stats(type="ethernet,network,wireless")).

        Raises:
            RuntimeError: the data can't be parsed.

        Returns:
            list[TachyonInterface]: One entry per port/bridge/radio.
        '''
        data = self.get_stats('ethernet,network,wireless')
        interfaces = []

        for name, port in data.get('ethernet', {}).get('ports', {}).items():
            interfaces.append(TachyonInterface(
                name=name,
                kind='ethernet',
                mac='',  # not reported per-port -- only switch_mac (the whole switch chip)
                link_up=port.get('link'),
                speed_mbps=port.get('speed'),
                duplex=port.get('duplex'),
            ))

        for zone_name, zone in data.get('network', {}).get('zones', {}).items():
            bridge = zone.get('data_bridge')
            if not bridge:
                continue
            interfaces.append(TachyonInterface(
                name=bridge.get('interface', f'br-{zone_name}'),
                kind='bridge',
                mac=bridge.get('mac', ''),
                link_up=None,  # not reported at the bridge level
                speed_mbps=None,
                duplex=None,
            ))

        for name, radio in data.get('wireless', {}).get('radios', {}).items():
            interfaces.append(TachyonInterface(
                name=name,
                kind='wireless',
                mac=radio.get('mac', ''),
                link_up=None,
                speed_mbps=None,
                duplex=None,
            ))

        return interfaces

    def get_ipaddresses(self) -> list[TachyonIPAddress]:
        '''Every IPv4/IPv6 address on every zone's bridge interface
        (stats(type="network")).

        Raises:
            RuntimeError: the data can't be parsed.

        Returns:
            list[TachyonIPAddress]: One entry per address.
        '''
        zones = self.get_stats('network').get('network', {}).get('zones', {})
        addresses = []

        for zone_name, zone in zones.items():
            bridge = zone.get('data_bridge')
            if not bridge:
                continue
            interface = bridge.get('interface', f'br-{zone_name}')

            for version, key in ((4, 'ipv4'), (6, 'ipv6')):
                block = bridge.get(key)
                if not block:
                    continue
                gateway = block.get('gateway')
                for address in block.get('ip_address', []):
                    addresses.append(TachyonIPAddress(
                        zone=zone_name,
                        interface=interface,
                        address=address,
                        version=version,
                        gateway=gateway,
                    ))

        return addresses

    def get_wireless(self) -> list[TachyonWirelessRadio]:
        '''Every radio and its connected peer(s) (stats(type="wireless")).

        `wireless.peers` is confirmed live to come back as an empty
        *dict* on a radio with nobody connected (e.g. an idle AP), but
        a *list* of peer dicts once something is - both are handled
        here rather than assuming one shape.

        Raises:
            RuntimeError: the data can't be parsed.

        Returns:
            list[TachyonWirelessRadio]: One entry per radio.
        '''
        wireless = self.get_stats('wireless').get('wireless', {})
        raw_peers = wireless.get('peers', [])
        peer_list = list(raw_peers.values()) if isinstance(raw_peers, dict) else raw_peers

        radios = []
        for name, radio in wireless.get('radios', {}).items():
            radios.append(TachyonWirelessRadio(
                name=name,
                mac=radio.get('mac', ''),
                op_mode=radio.get('op_mode', ''),
                ssid=radio.get('ssid', ''),
                freq_mhz=radio.get('freq'),
                channel=radio.get('channel'),
                channel_width_mhz=radio.get('channel_width'),
                security=radio.get('security', ''),
                # Confirmed live only a single radio (wlan0) is ever
                # present, so every peer belongs to it -- there's no
                # per-peer field naming which radio it's on.
                peers=[self._parse_peer(p) for p in peer_list],
            ))
        return radios

    def _parse_peer(self, peer: dict) -> TachyonWirelessPeer:
        return TachyonWirelessPeer(
            mac=peer.get('mac', ''),
            rssi=peer.get('rssi'),
            remote_rssi=peer.get('remote_rssi'),
            snr=peer.get('snr'),
            tx_mcs=peer.get('tx_mcs'),
            rx_mcs=peer.get('rx_mcs'),
            distance_m=peer.get('est_link_distance'),
            connection_time_seconds=peer.get('connection_time'),
        )

    def get_config(self, redact: bool = False) -> dict:
        '''Get the device's full configuration (config).

        Unredacted, it contains local user password hashes, the
        wireless passphrase and SNMP community - never log or print it
        wholesale. set_config() needs the unredacted form.

        Args:
            redact: Mask secrets (see redact_secrets()) for a copy
                safe to store.

        Raises:
            RuntimeError: the data can't be parsed.

        Returns:
            dict: Full device configuration.
        '''
        res = self._get('config')

        if res.status_code == 200:
            config = res.json()
            return redact_secrets(config) if redact else config

        raise RuntimeError(f"Error fetching config: {res.status_code} {res.text}")

    def set_config(self, config: dict, dry_run: bool = True) -> dict:
        '''Apply a full configuration (config).

        Defaults to dry_run=True (the API validates the config without
        applying it) - a caller has to pass dry_run=False explicitly to
        actually change anything on the device. This method itself is
        otherwise untested against real hardware (no config change has
        been confirmed live yet) - treat it as scaffolding to build on,
        not a verified-safe operation.

        Args:
            config: Full configuration document, in the same shape
                get_config() returns.
            dry_run: Validate only, without applying. Defaults to True.

        Raises:
            RuntimeError: the request failed or was rejected.

        Returns:
            dict: The API's response body.
        '''
        res = self._session.post(
            self._build_url('config'),
            json=config,
            params={'dry_run': 'true' if dry_run else 'false'},
            cookies={'api_token': self._auth_token},
            verify=self._verify_ssl,
            timeout=self._timeout,
        )

        if res.status_code == 200:
            return res.json()

        raise RuntimeError(f"Error setting config: {res.status_code} {res.text}")

    def reboot(self) -> None:
        '''Reboot the device (reboot).

        Untested against real hardware - scaffolding to build on, not
        a verified-safe operation. Never called automatically by
        anything in this package.

        Raises:
            RuntimeError: the request failed.
        '''
        res = self._session.post(
            self._build_url('reboot'),
            cookies={'api_token': self._auth_token},
            verify=self._verify_ssl,
            timeout=self._timeout,
        )

        if res.status_code != 200:
            raise RuntimeError(f"Error rebooting device: {res.status_code} {res.text}")
