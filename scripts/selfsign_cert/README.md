# Self-Signed Certificate & CSR Generator

A flexible Python script to generate **self-signed X.509 certificates** or **Certificate Signing Requests (CSRs)** with support for:

- RSA and ECDSA (P-256, P-384, P-521) keys
- Full X.509 subject fields
- Multiple export formats: PEM, DER (.cer), PKCS#8, and PKCS#12 (.p12/.pfx)
- Subject fields via CLI arguments **or** external config file (JSON/YAML)

Perfect for DevOps workflows, internal PKI, testing, Ansible automation, and containerized environments.

## Features

- **Key algorithms**: RSA (default) or ECDSA (recommended for modern performance)
- **Output formats**:
  - `x509_pem` → `.pem` (cert) + `.key`
  - `x509_der` → `.cer` (DER cert) + `.key`
  - `pkcs8` → PEM cert + PKCS#8 private key
  - `pkcs12` → Single encrypted `.p12` bundle (ideal for Java, Windows, browsers)
- **Subject configuration**: CLI flags **or** JSON/YAML config file (strict either/or)
- **CSR mode**: Generate CSRs for submission to real CAs (Let’s Encrypt, internal PKI, etc.)
- Works on Python 3.11+

## Requirements

```bash
# Using pip-tools (recommended)
pip install -r requirements.txt

# Or directly
pip install cryptography PyYAML
```

## Usage

### Using a Config File (Recommended for automation)

Create a configuration file with your subject details. Both `.json` and `.yaml` filetypes are supported. See for examples:
* `config/subject.json`
* `config/subject.yaml`


Run with config:

``` Bash
# Self-signed PEM (ECDSA)
python selfsign_cert.py --config config/subject.json --key-type ecdsa --curve P-384 --cert-type x509_pem

# PKCS#12 bundle (most common for applications)
python selfsign_cert.py --config config/subject.yaml --key-type ecdsa --cert-type pkcs12

# CSR for real CA signing
python selfsign_cert.py --config config/subject.json --mode csr --output-dir ./certs
```

### Using Command-Line Arguments (Quick / one-off)

``` Bash
# Basic RSA self-signed certificate
python selfsign_cert.py --common-name "test.example.com" --organization "TestCorp"

# Full subject with ECDSA + PKCS#12
python selfsign_cert.py \
  --common-name "api.prod.local" \
  --country US \
  --state "New York" \
  --locality "Albany" \
  --organization "MyCompany" \
  --ou "DevOps" \
  --key-type ecdsa \
  --curve P-384 \
  --cert-type pkcs12

# Generate CSR instead of self-signed
python selfsign_cert.py --common-name "www.example.com" --mode csr
```

## Options

### Common Options

| Option | Description | Default |
| --- | --- | --- |
| `--config, -c` | Path to `.json` or `.yaml` subject config file | None |
| `--key-type` | `rsa` or `ecdsa` | `rsa` |
| `--curve` | ECDSA curve (`P-256` \| `P-384` \| `P-521`) | `P-256` |
| `--key-size` | RSA key size in bits | `2048` |
| `--mode` | `selfsigned` or `csr` | `selfsigned` |
| `--cert-type` | `x509_pem`, `x509_der`, `pkcs12`, `pkcs8` | `x509_pem` |
| `--validity-days` | Validity period in days (self-signed only) | `365` |
| `--output-dir` | Output directory | `.` |
| `--password` | Encryption password for PKCS#12 / PKCS#8 | (prompt if needed) |

### Certificate Subject Options



> **IMPORTANT**: *`--config`* and certificate subject flags (*`--common-name`*, *`--country`*, etc.) are _**mutually exclusive**_. Mixing them will cause an **ERROR**.

| Option | Description |
| --- | --- |
| `--common-name` | Common Name (CN) |
| `--country` | Country (C) |
| `--state` | State/Province (ST) |
| `--locality` | Locality/City (L) |
| `--organization` | Organization (O) |
| `--ou` | Organizational Unit (OU) |
| `--email` | Email Address |
| `--serial` | Subject Serial Number |
| `--street` | Street Address |
| `--postal-code` | Postal Code |
| `--business-cat` | Business Category |


## Output Files

Depending on `--cert-type`:

* `x509_pem`  → `<name>.pem` (cert) + `<name>.key`
* `x509_der`  → `<name>.cer` (DER) + `<name>.key`
* `pkcs8`     → `<name>.pem` + `<name>.key` (PKCS#8 format)
* `pkcs12`    → `<name>.p12` (single encrypted bundle)
* `csr`       → `<name>.csr` + `<name>.key`

## Security Notices

* Self-signed certificates are for development, testing, and internal use only.
* For production services, use `--mode csr` and submit the CSR to a trusted Certificate Authority.
* PKCS#12 files are encrypted, but treat the resulting `.p12` file and password as sensitive.
* ECDSA keys offer better performance and smaller size than RSA with equivalent security.

## Troubleshooting

* "**Enter encryption password**" appears for PKCS#12 and encrypted PKCS#8.
* Make sure `cryptography>=43.0.0` is installed for full PKCS#12 support.
* Config file must contain *at least* `"common_name"`.

## When to Use Each Certificate Type

| Certificate Type | File Extensions       | Best Used For                                                                 | Real-World DevOps Scenarios |
|------------------|-----------------------|-------------------------------------------------------------------------------|-----------------------------|
| **x509_pem**     | `.pem` (cert) + `.key` | Most common format in Linux, Nginx, Apache, HAProxy, Python/Go apps, Docker | - Nginx / Traefik / Caddy reverse proxies<br>- Kubernetes TLS secrets (`tls.crt` + `tls.key`)<br>- Ansible playbooks deploying certs to servers<br>- Internal services talking over mTLS |
| **x509_der**     | `.cer` + `.key`       | Windows systems, Java keystores, some legacy applications                     | - Importing into Windows Certificate Store<br>- Java-based applications (Tomcat, Spring Boot)<br>- Some monitoring tools or older load balancers |
| **pkcs8**        | `.pem` (cert) + `.key` | Modern applications that require PKCS#8 private key format                    | - Newer Java versions (Java 9+ prefers PKCS#8)<br>- Applications using OpenSSL 3.x defaults<br>- When you need encrypted private keys in a standardized format |
| **pkcs12**       | `.p12` or `.pfx`      | Single-file bundle containing both certificate + private key (encrypted)      | - **Windows servers** (IIS)<br>- **Java / Tomcat** keystores (`keytool -importkeystore`)<br>- **Azure Application Gateway**, **AWS ELB**, **Google Cloud Load Balancer**<br>- Browser-based testing or client certificates<br>- Exporting certs for developers to import into their IDEs or Postman |