# SAML SP Demo Keys

The SAML2 example needs a private key and self-signed certificate for the SP
(service provider). They are intentionally **not committed** — generate your
own throwaway pair before running the example:

```bash
cd src/main/resources/saml

# Private key + self-signed cert, valid for 10 years
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout sp-private-key.pem \
    -out sp-certificate.pem \
    -days 3650 \
    -subj "/CN=cinetrack-sp/O=CineTrack/C=US"
```

Both files are ignored by `.gitignore` at the repo root. Regenerate at any time
— nothing in the application logic depends on a specific key identity.
