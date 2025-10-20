import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class Iso8583Sender {
    private static final String HOST = "hostigor";
    private static final int PORT = 8056;
    // Replace the value below with the ISO 8583 message to send, encoded as hexadecimal characters.
    private static final String HEX_MESSAGE =
            "3030303030303030303030303030303030303030303030303030303030303030";

    /**
     * When set to {@code true}, the client will trust every server certificate without validation.
     * This is insecure and should only be used in controlled environments where the server's
     * identity is already known.
     */
    private static final boolean TRUST_ALL_CERTIFICATES = true;

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

    private static SSLSocketFactory createSslSocketFactory() throws GeneralSecurityException {
        if (!TRUST_ALL_CERTIFICATES) {
            return (SSLSocketFactory) SSLSocketFactory.getDefault();
        }

        SSLContext context = SSLContext.getInstance("TLS");
        TrustManager[] trustManagers = new TrustManager[]{new TrustAllCertificatesManager()};
        context.init(null, trustManagers, new SecureRandom());
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

    private static final class TrustAllCertificatesManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // Intentionally left blank: all client certificates are trusted.
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // Intentionally left blank: all server certificates are trusted.
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
