# Post hoc check of algorithm registration (October 2026)

**Purpose.** To establish whether loading oqs-provider under OpenSSL 3.5.0 can make a second, provider-based implementation of X25519MLKEM768 available, which is a precondition for a within-release "native versus provider" comparison.

**Scope.** Functional check only, performed by the authors on 27 October 2026 in a separate environment (Ubuntu 24.04.5 LTS virtual machine, Intel Xeon Gold 5220R). It does not reproduce the original hosts, builds or benchmark runs, contains no timing measurements, and cannot show which implementation executed during the archived runs. Terminal transcripts were not archived; the observations are summarised below.

## Components

| Component | Version | Source commit |
|---|---|---|
| OpenSSL | 3.4.1 | `a26d85337dbdcd33c971f38eb3fa5150e75cea87` |
| OpenSSL | 3.5.0 | `636dfadc70ce26f2473870570bfd9ec352806b1d` |
| liboqs | 0.15.0 | `97f6b86b1b6d109cfd43cf276ae39c2e776aed80` |
| oqs-provider | 0.11.0-rc1 (the version recorded in the archived runs) | `ea899227c8f4b2901330340050fec07998143d1f` |

## Commands and observations

```sh
openssl list -providers -verbose
openssl list -kem-algorithms -provider default -provider oqsprovider
```

| Build | Observation |
|---|---|
| OpenSSL 3.4.1, default provider only | no ML-KEM algorithms listed |
| OpenSSL 3.4.1 + oqs-provider | `default` and `oqsprovider` active (provider reports liboqs 0.15.0); `mlkem768 @ oqsprovider`, `X25519MLKEM768 @ oqsprovider` |
| OpenSSL 3.5.0 + oqs-provider | `ML-KEM-768 @ default` and `X25519MLKEM768 @ default` only; no `X25519MLKEM768 @ oqsprovider`, while oqs-specific hybrids remain listed under `oqsprovider` |

Interoperability (`s_server` / `s_client -brief`, both restricted with `-groups X25519MLKEM768`, RSA self-signed certificate):

* OpenSSL 3.5.0 server and client: TLS 1.3 established; client prints `Negotiated TLS1.3 group: X25519MLKEM768`.
* OpenSSL 3.4.1 + oqs-provider server, OpenSSL 3.5.0 client: TLS 1.3 established, `TLS_AES_256_GCM_SHA384`, `rsa_pss_rsae_sha256`, `Negotiated TLS1.3 group: X25519MLKEM768`.

## Conclusion

With oqs-provider 0.11.0-rc1, OpenSSL 3.5.0 exposes X25519MLKEM768 only through its default (native) provider, which is consistent with the oqs-provider documentation for OpenSSL ≥ 3.5. If the archived OpenSSL 3.5.0 runs used the same provider version, as their metadata state, both runs labelled "provider" and "native" would have used the native implementation. Their difference is therefore treated as run-to-run variation of one configuration.
