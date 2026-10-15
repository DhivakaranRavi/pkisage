# Profile format

A profile describes what a CA accepts. Files live in `src/pkisage/profiles/` (or pass a path to `--profile`) and are validated by the `Profile` model.

```yaml
name: corp-web
allowed_key_types: [RSA, EC]
min_rsa_bits: 2048
allowed_curves: [secp256r1, secp384r1]
san_required: true          # also requires at least one DNS name
allowed_ekus: [serverAuth]
max_validity_days: 397
allowed_sig_algs: [sha256, sha384, sha512]
```

Bundled: `corp-web` (example policy), `old` and `new` (example old/new platform used by `migrate-check` and the demo). They are illustrative, not any vendor's real policy: derive your own from your CA's certificate profile settings.
