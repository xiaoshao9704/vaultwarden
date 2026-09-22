#!/usr/bin/env python3
"""Generate a CI-only Dockerfile: preserve the upstream runtime, add locked tests."""
from pathlib import Path

src = Path('docker/Dockerfile.alpine').read_text()
if 'cargo build --features ${DB}' not in src:
    raise SystemExit('Upstream Dockerfile changed: review before building')
src = src.replace('cargo build --features ${DB}', 'cargo build --locked --features ${DB}')
marker = '######################## RUNTIME IMAGE'
if src.count(marker) != 1:
    raise SystemExit('Cannot locate upstream runtime-stage boundary')
a = src.index(marker)
src = src[:a] + '''# The runtime COPY depends on this tested build stage.
RUN . /env-cargo && \\
    cargo test --locked --features ${DB} --profile "${CARGO_PROFILE}" --target="${CARGO_TARGET}" --bin vaultwarden

''' + src[a:]
# Do not change /data, the port, the user, the entry point, healthcheck, CA bundle,
# time zones, supported databases, or the web-vault asset image.
Path('docker/Dockerfile.pr7370-ci').write_text(src)
