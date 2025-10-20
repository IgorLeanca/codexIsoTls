# ISO 8583 Socket Sender

This repository contains a minimal Java 8 application that sends an ISO 8583 message, provided as a hexadecimal string, to the host `hostigor` on port `8056` over a TLS-encrypted socket.

## Prerequisites

- Java 8 JDK

## Building

```
javac src/Iso8583Sender.java
```

## Running

The ISO 8583 message is defined in `Iso8583Sender.HEX_MESSAGE`. Edit the constant to match the hexadecimal payload that should be transmitted.

After adjusting the constant if necessary, run the program:

```
java -cp src Iso8583Sender
```

The program establishes a TLS session with `hostigor:8056`, sends the decoded bytes, and prints any response as a hexadecimal string.

### Trusting the server certificate

`Iso8583Sender` contains a `CUSTOM_CA_CERT_PEM` constant that holds the PEM-encoded certificate authority (CA) or server certificate the client should trust. Replace the sample SecureTrust CA contents with your own PEM certificate if necessary. When the constant is left empty, the JVM's default trust store is used instead.

If you prefer to supply a separate trust store file, you can still run the program with the standard JVM options, for example:

```
java -Djavax.net.ssl.trustStore=/path/to/keystore -Djavax.net.ssl.trustStorePassword=changeit -cp src Iso8583Sender
```
