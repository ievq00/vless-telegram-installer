# External components

This repository contains an independent installer, administration application and
integration code. It does not use, download or include scripts from video tutorials.

The installer downloads these upstream projects at the exact versions and SHA-256
checksums recorded in `dependencies.lock.json`:

- [sing-box](https://github.com/SagerNet/sing-box): VLESS client.
- [Caddy](https://github.com/caddyserver/caddy): HTTPS, certificates and reverse proxy.
- [Telegram tproxy-server](https://github.com/telegramdesktop/tproxy-server): WEB relay protocol.
- [alexbers/mtprotoproxy](https://github.com/alexbers/mtprotoproxy): MTProto backend, with middle proxies disabled.
- [Go](https://go.dev/): compiler used to build the upstream WEB relay.

Their source code and binaries are fetched from their upstream locations at install
time; they are not included in this repository or the embedded installer bundle.
Each upstream component remains subject to its own terms. License files shipped
with downloaded source archives are retained under `/opt/vless-telegram/vendor`.

Python cryptography, PySocks and qrencode are installed from the operating system's
package repositories. The MIT license in this repository applies to this
repository's own code.
