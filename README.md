# Tachyon Networks Automations
[![Tests](https://github.com/dmcken/tach_automata/actions/workflows/tests.yml/badge.svg)](https://github.com/dmcken/tach_automata/actions/workflows/tests.yml)
[![Ruff](https://github.com/dmcken/tach_automata/actions/workflows/ruff.yml/badge.svg)](https://github.com/dmcken/tach_automata/actions/workflows/ruff.yml)

Automate the interfaces of Tachyon Networks fixed-wireless products,
via their officially documented RESTful API
(https://tachyon-networks.github.io/api_docs/).

## Modules / Hardware Platforms

Every model confirmed so far speaks the same versioned API under
`/cgi.lua/apiv1/`, so there's a single `TachyonDevice` class rather
than a per-model split:

- TNA-301, TNA-302, TNA-303X - verified against real units of each
- TNS-100 - documented, not yet verified against real hardware

Read-only for now: login and identify (`get_system_info()`) plus a raw
`get_stats()` escape hatch for anything else the API exposes. No
config/reboot/firmware-update support yet.

## Install

```sh
pip install "tach_automata @ git+https://github.com/dmcken/tach_automata.git@v0.1.0"
```

## Running tests

Pure unit tests (no live devices touched) - HTTP calls are mocked with
`requests-mock`.

```sh
uv sync --group dev  # or: pip install -e .[test]
uv run pytest        # or: pytest
```

## Examples

Login and identify:
```python
import tach_automata

dev = tach_automata.TachyonDevice('10.0.0.1')
dev.login(['current-password', 'old-password'])  # tries each in order
info = dev.get_system_info()
print(info.model, info.name, info.serial_no)
```
