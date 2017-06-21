# go-check-ssl-certificates

# Installation

```
make
```

# Usage

* options

```
  -connect string
        The remote addr. The format should be 'example.com:ssl_port'.
  -file string
        The certificates.
```

* Check the website

```
go-check-ssl-certificates -connect hiroakis.com:443
```

* Check the certificate file

```
go-check-ssl-certificates -file test_certificates/my-server.crt
```

* The result example

```
{
  "cn": "hiroakis.com",
  "not_after": "2018-04-14T02:51:26Z",
  "not_before": "2016-01-11T11:23:49Z",
  "dns_names": [
    "hiroakis.com"
  ],
  "signature_algorithm": "SHA256-RSA",
  "issuer": "RapidSSL SHA256 CA - G3",
  "organizations": [
    "GeoTrust Inc."
  ],
  "expiration": 25642324.493055414
}
```

# License

MIT
