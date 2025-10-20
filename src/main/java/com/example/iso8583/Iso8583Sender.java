package com.example.iso8583;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
     * Path to a PEM-encoded certificate authority (CA) or server certificate that should be trusted.
     * Provide an absolute or relative path to the certificate file. Leave the string empty to use the
     * default JVM trust store instead.
     */
    private static final String CUSTOM_CA_CERT_PATH = "";

    /**
     * Some TLS servers immediately drop the connection when they see an unsupported protocol such as
     * TLS 1.3. Set {@link #ENABLED_PROTOCOLS} to the list of versions that the remote host supports to
     * avoid the "Connection reset" error during the handshake. Leave the array empty to retain the
     * JVM defaults.
     */
    private static final String[] ENABLED_PROTOCOLS = {"TLSv1.2"};

    public static void main(String[] args) {
        try {
            System.out.println("Step 1: Preparing ISO 8583 payload from configured hex string.");
            byte[] messageBytes = hexToBytes(HEX_MESSAGE);
            System.out.println("Hex payload length: " + messageBytes.length + " bytes.");
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
        System.out.println("Step 2: Establishing TLS connection to " + HOST + ":" + PORT + ".");
        try (SSLSocket socket = createSslSocket();
             OutputStream out = new BufferedOutputStream(socket.getOutputStream());
             InputStream in = new BufferedInputStream(socket.getInputStream())) {

            SSLSession session = socket.getSession();
            System.out.println("Connected using " + session.getProtocol() + " / " + session.getCipherSuite());

            System.out.println("Step 3: Sending " + messageBytes.length + " bytes to host.");
            System.out.println(bytesToHex(messageBytes, messageBytes.length));

            out.write(messageBytes);
            out.flush();

            System.out.println("Step 4: Waiting for host response.");
            byte[] buffer = new byte[1024];
            int read = in.read(buffer);
            if (read == -1) {
                System.out.println("Step 5: No response received before the connection closed.");
            } else {
                System.out.println("Step 5: Received " + read + " bytes from host.");
                System.out.println(bytesToHex(buffer, read));
            }
        }
    }

    private static SSLSocket createSslSocket() throws IOException {
        try {
            SSLSocketFactory factory = createSslSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket(HOST, PORT);
            if (ENABLED_PROTOCOLS.length > 0) {
                socket.setEnabledProtocols(ENABLED_PROTOCOLS);
            }
            socket.startHandshake();
            return socket;
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to initialize SSL context", e);
        }
    }

    private static SSLSocketFactory createSslSocketFactory() throws GeneralSecurityException, IOException {
        if (CUSTOM_CA_CERT_PATH.trim().isEmpty()) {
            return (SSLSocketFactory) SSLSocketFactory.getDefault();
        }

        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Path certificatePath = Paths.get(CUSTOM_CA_CERT_PATH);
        if (!Files.exists(certificatePath)) {
            throw new IOException("Custom CA certificate file not found: " + CUSTOM_CA_CERT_PATH);
        }

        try (InputStream certStream = Files.newInputStream(certificatePath)) {
            X509Certificate certificate =
                    (X509Certificate) certificateFactory.generateCertificate(certStream);
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
