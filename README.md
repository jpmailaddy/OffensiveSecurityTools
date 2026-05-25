# Offensive Security Tools

A portfolio index of tools I've built for offensive / authorized
security testing. Each tool lives in its own repository so it can be
installed, versioned, and starred independently.

## Tools

### [apitest](https://github.com/jpmailaddy/apitest)

External API security posture scanner. Classifies REST / SOAP / GraphQL,
fingerprints the server, parses OpenAPI / GraphQL specs, enumerates
endpoints with soft-404 calibration + HTML crawling + method probing,
and runs OWASP API Top 10 passive checks. Includes ready-to-paste curl
replays for every finding, proxy support, rate limiting, custom headers,
and a hash-chained audit log.

```
go install github.com/jpmailaddy/apitest/cmd/apitest@latest
apitest scan https://api.example.com -d -y -r "Authorized engagement"
```

### [Subdomain_Enumeration](./Subdomain_Enumeration/)

Bash pipeline that drives subfinder, shuffledns, AltDNS, MassDNS,
gobuster, httpx, and (optionally) EyeWitness to enumerate, resolve,
and screenshot subdomains for a target domain. Lives in this repo
because it's a thin shell script rather than a standalone Go/Rust
project.

```
./Subdomain_Enumeration/Subdomain_script.sh -d example.com
```

See [Subdomain_Enumeration/README.md](./Subdomain_Enumeration/README.md)
for the required tooling.
