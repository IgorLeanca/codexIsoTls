# ISO 8583 Socket Sender

This repository contains a minimal Java 8 application that sends an ISO 8583 message, provided as a hexadecimal string, to the host `hostigor` on port `8056` over either a TLS-encrypted or plain TCP socket.

## Prerequisites

- Java 8 JDK
- Apache Maven 3.6+

## Building

### Option 1: Using Maven

Build the runnable JAR with Maven:

```
mvn -DskipTests package
```

The compiled artifact will be placed at `target/iso8583-sender-1.0-SNAPSHOT.jar`.

### Option 2: Using the bundled script (no Maven downloads)

If the server does not have internet access for Maven to download plugins, you can still build the
JAR using the provided helper script:

```
./build-jar.sh
```

This compiles the sources with `javac` and assembles `target/iso8583-sender-manual.jar`, which can
be copied straight to a Linux server and executed with `java -jar`.

## Running

The ISO 8583 message is defined in `src/main/java/com/example/iso8583/Iso8583Sender.java` as the `HEX_MESSAGE` constant. Edit the constant to match the hexadecimal payload that should be transmitted.

The binary defaults to TLS mode, but you can switch transports at launch time without recompiling:

```
java -jar target/iso8583-sender-1.0-SNAPSHOT.jar --no-tls
```

Passing `--no-tls` instructs the sender to use a plain TCP socket; omit the flag (or use `--use-tls`) to negotiate TLS and print the resulting protocol/cipher details.

Proxy traversal can likewise be toggled per run. By default the sender opens an HTTP CONNECT tunnel through `12.12.44.3:3128` before contacting `hostigor:8056`. To override that behavior and connect directly, start the program with `--no-proxy`. Supplying `--use-proxy` re-enables the tunnel.

If the remote endpoint only supports particular TLS protocol versions, adjust the `ENABLED_PROTOCOLS`
constant in the same file (for example, set it to `{"TLSv1.2"}`) to avoid the server closing the
connection during the handshake. Leaving the array empty retains the JVM defaults. The sender prints
when the TLS handshake begins and reports the negotiated protocol and cipher after it succeeds.

Trusted certificates can be stored in the `certificates.txt` file in the project root. The
application loads the PEM blocks listed in this file automatically when establishing the TLS
connection and logs how many entries were imported. The repository ships with the SecureTrust CA
certificate as an example entry—replace it with the certificate(s) issued for your environment.

After the message is transmitted, the client waits up to 10 seconds for a response before timing out
and closing the socket. Adjust the `RESPONSE_TIMEOUT_MILLIS` constant if your host requires a longer
window to reply.

After adjusting the constant if necessary, run the program either from the packaged JAR:

```
java -jar target/iso8583-sender-1.0-SNAPSHOT.jar
```

or directly from the sources using Maven:

```
mvn exec:java
```

The program establishes a TLS or TCP session (directly or via the configured proxy) with `hostigor:8056`, sends the decoded bytes, and prints any response as a hexadecimal string.

### Trusting the server certificate

`Iso8583Sender` reads trusted certificates from the UTF-8 text file referenced by the
`CUSTOM_CA_CERTIFICATE_LIST_PATH` constant (defaults to `certificates.txt`). Populate the file
with one or more PEM blocks—multiple certificates can be included back-to-back. Lines starting with
`#` are treated as comments and ignored.

When `CUSTOM_CA_CERTIFICATE_LIST_PATH` is set to an empty string, the JVM's default trust store is
used instead of the bundled list. This is useful when the endpoint already chains to a well-known
public CA.

If you prefer to supply a separate trust store file, you can still run the program with the standard
JVM options, for example:

```
java -Djavax.net.ssl.trustStore=/path/to/keystore -Djavax.net.ssl.trustStorePassword=changeit -jar target/iso8583-sender-1.0-SNAPSHOT.jar
```
