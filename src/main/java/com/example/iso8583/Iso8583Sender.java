package com.example.iso8583;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class Iso8583Sender {
    private static final String HOST = "hostigor";
    private static final int PORT = 8056;
    // Replace the value below with the ISO 8583 message to send, encoded as hexadecimal characters.
    private static final String HEX_MESSAGE =
            "3030303030303030303030303030303030303030303030303030303030303030";

    /**
     * Paste the PEM-encoded certificate of the issuing certificate authority (CA) or the server
     * certificate itself. The provided sample contains the SecureTrust CA that issued the hostigor
     * endpoint. If you prefer to use the default JVM trust store, leave this string empty.
     */
    private static final String CUSTOM_CA_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n"
                    + "MIIDuDCCAqCgAwIBAgIQDPCOXAgWpa1Cf/DrJxhZ0DANBgkqhkiG9w0BAQUFADBI\n"
                    + "MQswCQYDVQQGEwJVUzEgMB4GA1UEChMXU2VjdXJlVHJ1c3QgQ29ycG9yYXRpb24x\n"
                    + "FzAVBgNVBAMTDlNlY3VyZVRydXN0IENBMB4XDTA2MTEwNzE5MzExOFoXDTI5MTIz\n"
                    + "MTE5NDA1NVowSDELMAkGA1UEBhMCVVMxIDAeBgNVBAoTF1NlY3VyZVRydXN0IENv\n"
                    + "cnBvcmF0aW9uMRcwFQYDVQQDEw5TZWN1cmVUcnVzdCBDQTCCASIwDQYJKoZIhvcN\n"
                    + "AQEBBQADggEPADCCAQoCggEBAKukgeWVzfX2FI7CT8rU4niVWJxB4Q2ZQCQXOZEz\n"
                    + "Zum+4YOvYlyJ0fwkW2Gz4BERQRwdbvC4u/jep4G6pkjGnx29vo6pQT64lO0pGtSO\n"
                    + "0gMdA+9tDWccV9cGrcrI9f4Or2YlSASWC12juhbDCE/RRvgUXPLIXgGZbf2IzIao\n"
                    + "wW8xQmxSPmjL8xk037uHGFaAJsTQ3MBv396gwpEWoGQRS0S8Hvbn+mPeZqx2pHGj\n"
                    + "7DaUaHp3pLHnDi+BeuK1cobvomuL8A/b01k/unK8RCSc43Oz969XL0Imnal0ugBS\n"
                    + "8kvNU3xHCzaFDmapCJcWNFfBZveA4+1wVMeT4C4oFVmHursCAwEAAaOBnTCBmjAT\n"
                    + "BgkrBgEEAYI3FAIEBh4EAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB\n"
                    + "/zAdBgNVHQ4EFgQUQjK2FvoE/f5dS3rD/fdMQB1aQ68wNAYDVR0fBC0wKzApoCeg\n"
                    + "JYYjaHR0cDovL2NybC5zZWN1cmV0cnVzdC5jb20vU1RDQS5jcmwwEAYJKwYBBAGC\n"
                    + "NxUBBAMCAQAwDQYJKoZIhvcNAQEFBQADggEBADDtT0rhWDpSclu1pqNlGKa7UTt3\n"
                    + "6Z3q059c4EVlew3KW+JwULKUBRSuSceNQQcSc5R+DCMh/bwQf2AQWnL1mA6s7Ll/\n"
                    + "3XpvXdMc9P+IBWlCqQVxyLesJugutIxq/3HcuLHfmbx8IVQr5Fiiu1cprp6poxkm\n"
                    + "D5kuCLDv/WnPmRoJjeOnnyvJNjR7JLN4TJUXpAYmHrZkUjZfYGfZnMUFdAvnZyPS\n"
                    + "CPyI6a6Lf+Ew9Dd+/cYy2i2eRDAwbO4H3tI0/NL/QPZL9GZGBlSm8jIKYyYwa5vR\n"
                    + "3ItHuuG51WLQoqD0ZwV4KWMabwTW+MZMo5qxN7SN5ShLHZ4swrhovO0C7jE=\n"
                    + "-----END CERTIFICATE-----\n";

    public static void main(String[] args) {
        try {
            byte[] messageBytes = hexToBytes(HEX_MESSAGE);
            sendMessage(messageBytes);
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid hex message: " + e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("I/O error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void sendMessage(byte[] messageBytes) throws IOException {
        try (SSLSocket socket = createSslSocket();
             OutputStream out = new BufferedOutputStream(socket.getOutputStream());
             InputStream in = new BufferedInputStream(socket.getInputStream())) {

            SSLSession session = socket.getSession();
            System.out.println("Connected using " + session.getProtocol() + " / " + session.getCipherSuite());

            System.out.println("Sending " + messageBytes.length + " bytes:");
            System.out.println(bytesToHex(messageBytes, messageBytes.length));

            out.write(messageBytes);
            out.flush();

            byte[] buffer = new byte[1024];
            int read = in.read(buffer);
            if (read == -1) {
                System.out.println("No response received.");
            } else {
                System.out.println("Received " + read + " bytes:");
                System.out.println(bytesToHex(buffer, read));
            }
        }
    }

    private static SSLSocket createSslSocket() throws IOException {
        try {
            SSLSocketFactory factory = createSslSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket(HOST, PORT);
            socket.startHandshake();
            return socket;
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to initialize SSL context", e);
        }
    }

    private static SSLSocketFactory createSslSocketFactory() throws GeneralSecurityException, IOException {
        if (CUSTOM_CA_CERT_PEM.trim().isEmpty()) {
            return (SSLSocketFactory) SSLSocketFactory.getDefault();
        }

        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try (ByteArrayInputStream certStream =
                     new ByteArrayInputStream(CUSTOM_CA_CERT_PEM.getBytes(StandardCharsets.US_ASCII))) {
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certStream);
            keyStore.setCertificateEntry("custom-ca", certificate);
        }

        trustManagerFactory.init(keyStore);
        context.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
        return context.getSocketFactory();
    }

    private static byte[] hexToBytes(String hex) {
        String normalized = hex.replaceAll("\\s+", "");
        if (normalized.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length");
        }

        int length = normalized.length();
        byte[] data = new byte[length / 2];

        for (int i = 0; i < length; i += 2) {
            int high = Character.digit(normalized.charAt(i), 16);
            int low = Character.digit(normalized.charAt(i + 1), 16);
            if (high == -1 || low == -1) {
                throw new IllegalArgumentException("Non-hex character detected at position " + i);
            }
            data[i / 2] = (byte) ((high << 4) + low);
        }

        return data;
    }

    private static String bytesToHex(byte[] bytes, int length) {
        StringBuilder sb = new StringBuilder(length * 2);
        for (int i = 0; i < length; i++) {
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return sb.toString();
    }
}
