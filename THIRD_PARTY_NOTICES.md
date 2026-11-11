# Third-party notices

warpeer includes or depends on the following open-source components.

## usque-rs — MASQUE transport

- Source: <https://github.com/FireMasterK/usque-rs>
- Pinned commit: `813e4d8beef0e9ad309cc1d608384963aa18626a`
- License: MIT (see `vendor/usque-masque/LICENSE.md`)

`vendor/usque-masque` is a modified copy of the `usque-masque` crate. Changes:

- HTTP/2: enlarged the initial stream/connection windows and added the required
  `release_capacity` calls (the upstream reader stalled after the first ~64 KiB).
- HTTP/2: the sender now waits for stream capacity instead of dropping data when
  the peer's send window is full.
- Removed the optional `quiche` transport and its dependencies; only the `quinn`
  HTTP/3 backend is built.

`usque-crypto`, `usque-cloudflare-api` and `usque-config` are consumed as
unmodified git dependencies from the same commit.

The Go implementation [usque](https://github.com/Diniboy1123/usque) was used as a
protocol reference (registration fields, SNI, MASQUE endpoint behaviour).

## h3

- Source: <https://github.com/hyperium/h3>, crate `h3` 0.0.8
- License: MIT / Apache-2.0 (see `vendor/h3/LICENSE`)

`vendor/h3` is a copy of `h3` 0.0.8 with the small patch from usque-rs applied: it
adds the non-standard `cf-connect-ip` protocol token that Cloudflare's MASQUE
endpoint requires. The patch itself is in the upstream usque-rs repository under
`vendor/h3.patch`.

## Other dependencies

All other Rust dependencies are listed in `Cargo.lock` and retain their own
licenses.
