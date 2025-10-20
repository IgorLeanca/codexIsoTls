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

The program establishes a TLS session with `hostigor:8056`, sends the decoded bytes, and prints any response as a hexadecimal string. By default the client trusts every certificate it encounters so that it can connect to servers using self-signed or private CA certificates. For production usage update `Iso8583Sender.TRUST_ALL_CERTIFICATES` to `false` and provide an appropriate trust store (for example via the standard `javax.net.ssl.trustStore` system properties).
