# RGW STS kid selection microbenchmark

Measured the original `93be2376f7a` key-selection/verification path against
`f296fa7f7e6`'s `select_jwks_keys()` with generated RS256 / RSA-2048 JWTs.
The original path reserializes JWKS elements and parses them individually;
the patched path selects from the already-parsed JWKS. Both use the same
Ceph jwt-cpp header and the same linked Ceph/OpenSSL dependencies.

This is a local CPU microbenchmark, not an RGW server or S3 benchmark.
It includes JWT decoding, JWKS parsing, key reconstruction/certificate parsing,
and signature verification. It excludes HTTP, DNS, TLS, provider/role lookups,
thumbprint checks, and logging. Certificate tests use one x5c certificate per
key and model the path where per-key thumbprint checks are skipped.
Tokens and keys are synthetic. No cluster credentials were used.

Environment: Ubuntu 24.04 ARM64 in a local Apple ARM Podman VM (6 vCPU),
GCC 13.3, OpenSSL 3.0.13. The benchmark and current ceph_json.cc use -O2 -g0;
existing Ceph common, json_spirit, fmt and Boost artifacts were reused from a
Debug build. Absolute timings are specific to this mixed local build and VM.
Each timing is the median of seven batches of 200 validations after 20 warmups.
Selection-only timing uses the same parsed objects and 3,000 calls per batch;
single-verification timing uses an already-parsed matching JWK. These columns
exclude the full JWKS parse. All keys in performance cases are RSA signing
keys. Positions are one-based. Fewer failed attempts and removal of reparsing
both contribute to the full-path timing difference.

## Reproduce

Requires Python cryptography, a compatible Linux Ceph build containing
libceph-common.so, fmt and Boost, and a checkout containing the selection patch.
Use CEPH_DEP_SOURCE_DIR if the initialized fmt submodule lives in another checkout.
Set CEPH_DEBUG_MUTEX to match the existing library ABI.

```sh
python3 generate.py ./fixtures
cmake -S . -B build -G Ninja \
  -DCEPH_SOURCE_DIR=/path/to/patched/ceph \
  -DCEPH_BUILD_DIR=/path/to/existing/ceph/build \
  -DCEPH_DEP_SOURCE_DIR=/path/to/initialized/ceph \
  -DCEPH_DEBUG_MUTEX=ON
cmake --build build -j2
./build/bench_sts_jwks ./fixtures > results.csv
./build/bench_sts_jwks ./fixtures --semantics-only
```

Generated keys are random, so rerun values will differ. Fixtures are not
committed. `results.csv` contains the recorded performance run; `semantics.log`
also checks kid-less tokens against a single JWK with and without a JWK kid.
The unknown-kid rejection mode is an experimental comparison, not a production
code change. It retains missing-kid fallback and rejects an explicitly supplied
kid that cannot be matched (including a supplied empty string without a matching
empty JWK kid). It does not enforce every OIDC profile requirement.

## Fallback review

- RFC 7515 section 4.1.4 makes the JWT kid optional. RFC 7517 section 4.5 also
  makes the JWK kid optional. Removing all fallback would reject valid kid-less
  single-key tokens; the signed fixtures demonstrate this case.
- OIDC Core section 10.1 requires a header kid when the referenced JWKS contains
  multiple keys. Section 10.1.1 uses that kid to identify the verification key
  during rotation and describes fetching new keys for an unfamiliar kid.
- Kubernetes v1.34's static public key getter returns all keys for an unspecified
  key ID and only matching keys for a specified ID. An empty result is rejected.
- go-oidc's RemoteKeySet tries all keys for a missing/empty kid, but only matching
  keys for a nonempty kid, including after fetching fresh keys. No matching key
  ultimately results in a verification error.
- Current RGW fetches the JWKS on each asymmetric STS verification. Rejecting an
  explicitly supplied but unmatched kid is therefore a reasonable OIDC policy;
  it is not a universal MUST-reject rule stated by base JWS. Removing that
  fallback changes existing acceptance behavior and should be explicit.

Sources:
- https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4
- https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5
- https://openid.net/specs/openid-connect-core-1_0.html#Signing
- https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
- https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/serviceaccount/jwt.go
- https://github.com/coreos/go-oidc/blob/v3/oidc/jwks.go
