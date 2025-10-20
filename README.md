# ISO 8583 Socket Sender

This repository contains a minimal Java 8 application that sends an ISO 8583 message, provided as a hexadecimal string, to the host `hostigor` on port `8056` over a TLS-encrypted socket.

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

If the remote endpoint only supports particular TLS protocol versions, adjust the `ENABLED_PROTOCOLS`
constant in the same file (for example, set it to `{"TLSv1.2"}`) to avoid the server closing the
connection during the handshake. Leaving the array empty retains the JVM defaults.

After adjusting the constant if necessary, run the program either from the packaged JAR:

```
java -jar target/iso8583-sender-1.0-SNAPSHOT.jar
```

or directly from the sources using Maven:

```
mvn exec:java
```

The program establishes a TLS session with `hostigor:8056`, sends the decoded bytes, and prints any response as a hexadecimal string.

### Trusting the server certificate

`Iso8583Sender` contains a `CUSTOM_CA_CERT_PATH` constant that points to a PEM-encoded certificate authority (CA) or server certificate file the client should trust. Set the constant to the absolute or relative path of your certificate file (for example, `certs/securetrust.pem`). When the constant is left empty, the JVM's default trust store is used instead.

The certificate file can contain either the issuing CA or the specific server certificate. Only one certificate is loaded from the file; if you need to trust multiple certificates, convert them into a Java KeyStore and launch the program with the standard JVM options.

If you prefer to supply a separate trust store file, you can still run the program with the standard JVM options, for example:

```
java -Djavax.net.ssl.trustStore=/path/to/keystore -Djavax.net.ssl.trustStorePassword=changeit -jar target/iso8583-sender-1.0-SNAPSHOT.jar
```
