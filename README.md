# Fastdialer

[![License](https://img.shields.io/github/license/projectdiscovery/fastdialer)](LICENSE.md)
![Go version](https://img.shields.io/github/go-mod/go-version/projectdiscovery/fastdialer?filename=go.mod)
[![Release](https://img.shields.io/github/release/projectdiscovery/fastdialer)](https://github.com/projectdiscovery/fastdialer/releases/)
[![Checks](https://github.com/projectdiscovery/fastdialer/actions/workflows/build-test.yml/badge.svg)](https://github.com/projectdiscovery/fastdialer/actions/workflows/build-test.yml)
[![GoDoc](https://pkg.go.dev/badge/projectdiscovery/fastdialer)](https://pkg.go.dev/github.com/projectdiscovery/fastdialer/fastdialer)


Fastdialer is implementation of `net.Dialer` with lot of features like DNS Cache , Dial History etc

# Features

- DNS Cache
- Dial History
- Supports Memory/Hybrid/Disk Cache.
- Supports Old/New TLS and x509 versions
- Supports Resolution Using Hosts File
- Cross Platform and more..

For more details and documentation refer [GoDoc](https://pkg.go.dev/github.com/projectdiscovery/fastdialer/fastdialer).


### ZTLS Fallback

When the TLS handshake of `DialTLS` or `DialTLSWithConfig` fails, fastdialer retries it once with zcrypto (ztls), to reach servers that `crypto/tls` rejects, such as servers with old TLS versions or legacy ciphers. The retry uses `ztls.ChromeCiphers` and the default ztls curves instead of the cipher suites and curve preferences of the config. It retries only when:

- the dial context isn't done, the handshake didn't time out, and the server's reply, if any, was TLS.
- the TLS config allows versions older than TLS 1.3.
- the TLS config uses nothing that zcrypto can't carry over: `InsecureSkipVerify` is `true`, and the config sets no `VerifyPeerCertificate` or `VerifyConnection` callback, no `GetClientCertificate`, and no Encrypted Client Hello settings. A `Certificates` chain is copied onto the retry. Otherwise the retry would verify the server differently, omit a certificate chosen by callback, or send the hidden server name in the clear.

Plain dials, including dials through a proxy, impersonated dials and ztls dials never fall back. A dial that falls back returns a `*ztls.Conn` instead of a `*tls.Conn`, which `WithTLSData` doesn't record. If the retry fails too, the error includes both failures.

To disable the fallback, set `DisableZtlsFallback` in the options or `DISABLE_ZTLS_FALLBACK=true` in the environment. Either one is enough.

### Pinning a Host to an IP

`WithResolveOverride` makes dials to one host connect to the given IP instead of resolving it, like `curl --resolve`. The hostname is still sent as SNI, and other hosts dialed with the same context, such as redirect targets or a proxy, are resolved as usual.

```go
ctx := fastdialer.WithResolveOverride(context.Background(), "example.com", "192.0.2.10")
conn, err := dialer.DialTLS(ctx, "tcp", "example.com:443")
```

# Example

An Example showing usage of fastdialer as a library is specified [here](./example/main.go)

```
cd example/
go run main.go
```

# License

fastdialer is distributed under MIT License
