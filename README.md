# gpgme-sq

A drop-in `LD_PRELOAD` shim that implements the GPGME API subset used by
**pacman / libalpm** (`signing.c`) entirely via subprocess calls to
[`gpg-sq`](https://gitlab.com/sequoia-pgp/sequoia-chameleon-gnupg) — the
Sequoia Chameleon GnuPG-compatible CLI.  No `gpg-agent`, no `pinentry`, no
display required.

## Why

`gpg-agent` requires a TTY or a display for the Pinentry dialog.  In
headless/CI/container environments this breaks `pacman -Sy`.  `gpg-sq` speaks
the same `--status-fd` protocol but never invokes Pinentry for *signature
verification*, making it suitable for those environments.

## Files

```
gpgme-sq/
├── src/
│   └── gpgme-sq.c      # Implementation
├── meson.build         # Meson build (preferred)
├── Makefile            # GNU make alternative
├── PKGBUILD            # Arch Linux package build
├── gpgme-sq.pc.in      # pkg-config template
└── README.md
```

## Build

### Meson (recommended)

```sh
meson setup build --buildtype=release
meson compile -C build
sudo meson install -C build
```

### GNU Make

```sh
make
sudo make install
```

### Arch Linux (makepkg)

```sh
makepkg -si
```

## Usage

```sh
# One-shot
LD_PRELOAD=/usr/local/lib/libgpgme-sq.so.11 pacman -Sy

# Persistent (system-wide) — add to /etc/ld.so.preload
echo /usr/local/lib/libgpgme-sq.so.11 | sudo tee /etc/ld.so.preload
```

## Implemented GPGME surface

| Function | Notes |
|---|---|
| `gpgme_check_version` | Returns `"1.23.2"` |
| `gpgme_engine_check_version` | Checks `gpg-sq` is executable |
| `gpgme_set_engine_info` | Stores `home_dir` globally |
| `gpgme_get_engine_info` | Returns static engine record |
| `gpgme_new` / `gpgme_release` | Context alloc/free |
| `gpgme_set/get_keylist_mode` | Stored per-context |
| `gpgme_data_new_from_mem` | Both copy and no-copy modes |
| `gpgme_data_new_from_stream` | Reads entire `FILE*` |
| `gpgme_data_release` | Frees buffer if owned |
| `gpgme_op_verify` | Detached-sig via `gpg-sq --verify` |
| `gpgme_op_verify_result` | Returns parsed signature list |
| `gpgme_get_key` | Local or external key lookup |
| `gpgme_key_ref` / `gpgme_key_unref` | Ref-counted key lifetime |
| `gpgme_op_import_keys` | `--recv-keys` by fingerprint |
| `gpgme_op_import_result` | Stub (considered=1, imported=1) |
| `gpgme_strerror` | Common error codes |
| `gpgme_set_locale` | No-op |

## Caveats

- Only `GPGME_PROTOCOL_OpenPGP` is supported.
- `gpgme_op_import_keys` always reports success; it does not parse the
  actual `--status-fd` import results.
- The `plaintext` argument to `gpgme_op_verify` is ignored (detached-sig
  mode only).
- Temp files are written under `/tmp`; ensure that is writable.
