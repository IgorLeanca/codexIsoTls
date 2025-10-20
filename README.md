# ISO 8583 Socket Sender

This repository contains a minimal Java 8 application that sends an ISO 8583 message, provided as a hexadecimal string, to the host `hostigor` on port `8056`.

## Prerequisites

- Java 8 JDK

## Building

```
javac src/Iso8583Sender.java
```

## Running

Pass the ISO 8583 payload as a hexadecimal string. Whitespace is ignored and may be used for readability.

```
java -cp src Iso8583Sender <hex-message>
```

Example:

```
java -cp src Iso8583Sender "6000400004A0200000000000000000011234567890ABCDEF"
```

The program connects to `hostigor:8056`, sends the decoded bytes, and prints any response as a hexadecimal string.
