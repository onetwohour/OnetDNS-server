# Test fixtures

`rsa_test_private_key_2048.pk8.b64` is an insecure, non-secret test key. It is
used only by `#[cfg(test)]` code to exercise DNSSEC and TLS RSA verification.
Never load or ship it as a production credential.

The decoded bytes are from `ring` 0.17.14's
`tests/rsa_test_private_key_2048.p8` fixture and retain that project's license.
`ring` itself is no longer a dependency; RSA verification is implemented in
`onetdns-core/src/rsa.rs`, and the fixture is now read by that module's
test-only signer (`rsa::testsign`).
