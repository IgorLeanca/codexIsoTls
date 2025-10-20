# ISO 8583 TLS CLI

A compact Java 8 command line client that sends raw ISO 8583:1993 messages over a TLS 1.2 socket with hostname verification and SNI.

## Building

```bash
mvn -q -e -DskipTests package
```

The shaded executable JAR is written to `target/iso-tls-1.0.0-shaded.jar`.

## Usage

```bash
java -jar target/iso-tls-1.0.0-shaded.jar --hex "<HEX>" [options]
```

Key options:

| Option | Description |
| ------ | ----------- |
| `--host`, `--port` | Override the default `hostigor:3333` endpoint. |
| `--hex` | Raw ISO 8583 payload in hex (spaces ignored). |
| `--message-already-framed` | Send bytes exactly as provided without adding prefixes. |
| `--prepend-length` | Prepend a 0/2/4-byte MLI. Combine with `--endianness` and `--length-includes-prefix`. |
| `--tpdu-hex` | Prepend a TPDU (hex). |
| `--read` | `expect-header` (default), `fixed`, or `until-close`. |
| `--read-header-length` | Header width (2 or 4 bytes) when `expect-header` is used. |
| `--read-header-endianness` | Endianness (`big` default). |
| `--read-header-includes-prefix` | Header length includes its own bytes. |
| `--bytes` | Number of bytes to read when `--read fixed` is selected. |
| `--save-response` | Write response hex to a file. |
| `--verbose` | Enable debug logging (sensitive values redacted automatically). |
| `--truststore`, `--truststore-pass`, `--truststore-type` | Custom trust store configuration. |
| `--keystore`, `--keystore-pass`, `--keystore-type` | Client certificate configuration for mTLS. |

Examples:

Send pre-framed message with 2-byte big-endian MLI, expect header on read:

```bash
java -jar target/iso-tls-1.0.0-shaded.jar \
  --host hostigor --port 3333 \
  --hex "<HEX>" \
  --prepend-length 2 \
  --read expect-header
```

Send exactly as provided, no MLI, read until close:

```bash
java -jar target/iso-tls-1.0.0-shaded.jar \
  --host hostigor --port 3333 \
  --hex "<HEX>" \
  --message-already-framed \
  --read until-close
```

Save the response and use a TPDU:

```bash
java -jar target/iso-tls-1.0.0-shaded.jar \
  --hex "<ISO-HEX>" \
  --tpdu-hex "6000000000" \
  --prepend-length 2 \
  --read expect-header \
  --save-response /tmp/resp.hex
```

## TLS stores

Create a PKCS12 truststore from a PEM chain:

```bash
keytool -importcert -alias hostigor-ca \
  -file hostigor-ca.pem \
  -keystore truststore.p12 \
  -storetype PKCS12 \
  -storepass changeit
```

Create a client keypair for mTLS:

```bash
keytool -genkeypair -alias iso-client \
  -keyalg RSA -keysize 2048 \
  -keystore keystore.p12 \
  -storetype PKCS12 \
  -storepass changeit \
  -dname "CN=iso-client"
```

Use those stores:

```bash
java -jar target/iso-tls-1.0.0-shaded.jar \
  --hex "<HEX>" \
  --truststore truststore.p12 --truststore-pass changeit --truststore-type PKCS12 \
  --keystore keystore.p12 --keystore-pass changeit --keystore-type PKCS12
```

## Logging

By default only high-level information is emitted. Pass `--verbose` to enable debug logging for troubleshooting (hex dumps remain, but sensitive passwords are not logged).
