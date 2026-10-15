#!/usr/bin/env bash
set -euo pipefail
: "${IMAGE:?Set IMAGE to the locally built image}"
: "${BASELINE_IMAGE:=vaultwarden/server:1.37.4}"
prefix="vw-pr7370-${RANDOM}-$$"
volume="${prefix}-data"
container="${prefix}-server"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker volume create "$volume" >/dev/null
wait_healthy() {
  local i status
  for i in $(seq 1 60); do
    status="$(docker inspect --format '{{.State.Status}}' "$container")"
    if [[ "$status" != running ]]; then
      docker logs "$container" >&2
      return 1
    fi
    if docker exec "$container" /healthcheck.sh >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  docker logs "$container" >&2
  echo 'Container did not become healthy' >&2
  return 1
}
start_container() {
  local image="$1" allowed="$2"
  docker run -d --name "$container" \
    --mount "type=volume,src=${volume},dst=/data" \
    -e DOMAIN=http://localhost -e SIGNUPS_ALLOWED=false \
    -e PASSKEY_LOGIN_ALLOWED="$allowed" \
    "$image" >/dev/null
  wait_healthy
}
# A synthetic empty-database migration fixture, NOT a real-vault recovery test.
docker pull "$BASELINE_IMAGE" >/dev/null
start_container "$BASELINE_IMAGE" false
docker exec "$container" sh -c 'test -s /data/db.sqlite3; printf "%s" fixture-preserved > /data/pr7370-fixture'
docker rm -f "$container" >/dev/null

start_container "$IMAGE" false
docker exec "$container" sh -c 'test -s /data/db.sqlite3; test "$(cat /data/pr7370-fixture)" = fixture-preserved'
# A disabled feature must not issue authentication challenges.
code="$(docker exec "$container" curl -sS -o /dev/null -w '%{http_code}' http://localhost/identity/accounts/webauthn/assertion-options)"
[[ "$code" == 4* ]] || { echo "Expected challenge denial, got HTTP $code" >&2; exit 1; }
docker exec "$container" curl -fsS http://localhost/api/config >/dev/null
docker exec "$container" curl -fsS http://localhost/ >/dev/null
# Confirm that a second process can reopen the migrated data directory.
docker restart "$container" >/dev/null
wait_healthy
docker rm -f "$container" >/dev/null

start_container "$IMAGE" true
docker exec "$container" curl -fsS http://localhost/identity/accounts/webauthn/assertion-options > "${prefix}-challenge.json"
# Lifetime comes from ASSERTION_CHALLENGE_TTL_SECS (bitwarden/server
# WebAuthnLoginAssertionOptionsTokenable.TokenLifeTime, 17 minutes).
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "${prefix}-challenge.json" "$repo_root/src/db/models/webauthn_challenge.rs" <<'PY'
import base64, json, re, sys
from pathlib import Path

def assertion_challenge_ttl_secs(source: str) -> int:
    match = re.search(
        r'pub const ASSERTION_CHALLENGE_TTL_SECS:\s*i64\s*=\s*([^;]+);',
        source,
    )
    if match is None:
        raise AssertionError('ASSERTION_CHALLENGE_TTL_SECS missing from webauthn_challenge.rs')
    expr = ''.join(match.group(1).split())
    factors = expr.split('*')
    if not factors or any(not factor.isdigit() for factor in factors):
        raise AssertionError(f'unsupported ASSERTION_CHALLENGE_TTL_SECS expression: {expr!r}')
    ttl = 1
    for factor in factors:
        ttl *= int(factor)
    return ttl

challenge_path = Path(sys.argv[1])
try:
    response = json.loads(challenge_path.read_text())
    parts = response['token'].split('.')
    claims = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)))
    assert 'state' not in claims, 'Server state leaked into JWT'
    assert isinstance(claims['jti'], str) and len(claims['jti']) >= 32
    ttl = assertion_challenge_ttl_secs(Path(sys.argv[2]).read_text())
    lifetime = claims['exp'] - claims['nbf']
    assert lifetime == ttl, (
        f'assertion JWT lifetime {lifetime}s != ASSERTION_CHALLENGE_TTL_SECS {ttl}s '
        '(bitwarden/server WebAuthnLoginAssertionOptionsTokenable)'
    )
    assert response['options']['userVerification'] == 'required'
    assert response['options'].get('allowCredentials', []) == []
finally:
    challenge_path.unlink(missing_ok=True)
PY
# This only checks server challenge issuance and runtime compatibility.
# Browser assertion verification, PRF decryption and replay E2E remain separate gates.
docker image inspect "$IMAGE" --format 'arch={{.Architecture}} bytes={{.Size}}'
echo 'Synthetic migration, restart, healthcheck, web vault and challenge-shape smoke tests passed.'
