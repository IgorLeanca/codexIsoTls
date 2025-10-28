package com.example.iso8583;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

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
     * Toggle between TLS (true) and plain TCP (false) connections. When TLS is disabled the
     * application skips all certificate handling and uses an unencrypted socket.
     */
    private static final boolean DEFAULT_USE_TLS = true;

    /**
     * Toggle whether traffic should be routed through an HTTP CONNECT proxy. When enabled the
     * program tunnels the TCP stream through the proxy before optionally starting the TLS handshake.
     */
    private static final boolean DEFAULT_USE_PROXY = true;

    /** Proxy host used when {@link #USE_PROXY} is enabled. */
    private static final String PROXY_HOST = "12.12.44.3";

    /** Proxy port used when {@link #USE_PROXY} is enabled. */
    private static final int PROXY_PORT = 3128;

    /**
     * Path to a UTF-8 text file that contains one or more PEM-encoded certificates that should be
     * trusted. Leave the string empty to use the default JVM trust store instead.
     */
    private static final String CUSTOM_CA_CERTIFICATE_LIST_PATH = "certificates.txt";

    /**
     * Some TLS servers immediately drop the connection when they see an unsupported protocol such as
     * TLS 1.3. Set {@link #ENABLED_PROTOCOLS} to the list of versions that the remote host supports to
     * avoid the "Connection reset" error during the handshake. Leave the array empty to retain the
     * JVM defaults.
     */
    private static final String[] ENABLED_PROTOCOLS = {"TLSv1.2"};

    /**
     * Maximum time to wait for the host to respond after sending the payload, in milliseconds. When
     * the timeout elapses the program logs that no response was received and closes the connection.
     */
    private static final int RESPONSE_TIMEOUT_MILLIS = 10_000;

    public static void main(String[] args) {
        try {
            System.out.println("Step 1: Preparing ISO 8583 payload from configured hex string.");
            byte[] messageBytes = hexToBytes(HEX_MESSAGE);
            System.out.println("Hex payload length: " + messageBytes.length + " bytes.");
            RuntimeConfig config = RuntimeConfig.fromArgs(args);
            sendMessage(messageBytes, config);
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid hex message: " + e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("I/O error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void sendMessage(byte[] messageBytes, RuntimeConfig config) throws IOException {
        String connectionLabel = config.useTls ? "TLS" : "TCP";
        if (config.useProxy) {
            System.out.println("Step 2: Establishing " + connectionLabel + " connection to " + HOST + ":"
                    + PORT + " via proxy " + PROXY_HOST + ":" + PROXY_PORT + ".");
        } else {
            System.out.println("Step 2: Establishing " + connectionLabel + " connection to " + HOST + ":"
                    + PORT + ".");
        }

        try (Socket socket = config.useTls ? createSslSocket(config) : createTcpSocket(config);
             OutputStream out = new BufferedOutputStream(socket.getOutputStream());
             InputStream in = new BufferedInputStream(socket.getInputStream())) {

            if (config.useTls) {
                SSLSocket sslSocket = (SSLSocket) socket;
                SSLSession session = sslSocket.getSession();
                System.out.println(
                        "Connected using " + session.getProtocol() + " / " + session.getCipherSuite());
            } else {
                System.out.println("Connected using plain TCP socket (no TLS encryption).");
            }

            socket.setSoTimeout(RESPONSE_TIMEOUT_MILLIS);

            System.out.println("Step 3: Sending " + messageBytes.length + " bytes to host.");
            System.out.println(bytesToHex(messageBytes, messageBytes.length));

            out.write(messageBytes);
            out.flush();

            System.out.println("Step 4: Waiting for host response.");
            byte[] buffer = new byte[1024];
            try {
                int read = in.read(buffer);
                if (read == -1) {
                    System.out.println("Step 5: No response received before the connection closed.");
                } else {
                    System.out.println("Step 5: Received " + read + " bytes from host.");
                    System.out.println(bytesToHex(buffer, read));
                }
            } catch (SocketTimeoutException timeout) {
                System.out.println("Step 5: No response received within " + RESPONSE_TIMEOUT_MILLIS
                        + " ms; closing the connection.");
            }
        }
    }

    private static SSLSocket createSslSocket(RuntimeConfig config) throws IOException {
        try {
            SSLSocketFactory factory = createSslSocketFactory();
            Socket baseSocket = createConnectedSocket(config);
            SSLSocket socket = (SSLSocket) factory.createSocket(baseSocket, HOST, PORT, true);
            if (ENABLED_PROTOCOLS.length > 0) {
                socket.setEnabledProtocols(ENABLED_PROTOCOLS);
            }
            System.out.println("Performing TLS handshake...");
            socket.startHandshake();
            return socket;
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to initialize SSL context", e);
        }
    }

    private static Socket createTcpSocket(RuntimeConfig config) throws IOException {
        return createConnectedSocket(config);
    }

    private static Socket createConnectedSocket(RuntimeConfig config) throws IOException {
        if (!config.useProxy) {
            return new Socket(HOST, PORT);
        }

        System.out.println("Connecting to proxy " + PROXY_HOST + ":" + PROXY_PORT + "...");
        Socket proxySocket = new Socket(PROXY_HOST, PROXY_PORT);
        establishProxyTunnel(proxySocket);
        return proxySocket;
    }

    private static void establishProxyTunnel(Socket proxySocket) throws IOException {
        String connectRequest = "CONNECT " + HOST + ":" + PORT + " HTTP/1.1\r\n"
                + "Host: " + HOST + ":" + PORT + "\r\n"
                + "Connection: keep-alive\r\n\r\n";

        OutputStream proxyOut = proxySocket.getOutputStream();
        proxyOut.write(connectRequest.getBytes(StandardCharsets.ISO_8859_1));
        proxyOut.flush();

        InputStream proxyIn = proxySocket.getInputStream();

        String responseLine = readProxyResponseLine(proxyIn);
        if (!(responseLine.startsWith("HTTP/1.1 200") || responseLine.startsWith("HTTP/1.0 200"))) {
            throw new IOException("Proxy CONNECT failed: " + responseLine);
        }

        // Drain the remaining headers until the blank line delimiter so the socket is ready for
        // ISO 8583 payload traffic.
        discardProxyHeaders(proxyIn);
        System.out.println("Proxy tunnel established successfully.");
    }

    private static String readProxyResponseLine(InputStream in) throws IOException {
        StringBuilder status = new StringBuilder();
        int previous = -1;
        int current;
        while ((current = in.read()) != -1) {
            if (current == '\n' && previous == '\r') {
                status.setLength(status.length() - 1); // remove carriage return
                break;
            }
            status.append((char) current);
            previous = current;
        }
        if (status.length() == 0) {
            throw new IOException("Empty response from proxy when establishing tunnel");
        }
        return status.toString();
    }

    private static void discardProxyHeaders(InputStream in) throws IOException {
        int state = 0;
        int b;
        while ((b = in.read()) != -1) {
            switch (state) {
                case 0:
                case 2:
                    if (b == '\r') {
                        state++;
                    } else {
                        state = 0;
                    }
                    break;
                case 1:
                    if (b == '\n') {
                        state++;
                    } else {
                        state = 0;
                    }
                    break;
                case 3:
                    if (b == '\n') {
                        return;
                    } else {
                        state = 0;
                    }
                    break;
                default:
                    throw new IllegalStateException("Unexpected state while discarding proxy headers");
            }
        }
        throw new IOException("Unexpected end of stream while reading proxy response headers");
    }

    private static SSLSocketFactory createSslSocketFactory() throws GeneralSecurityException, IOException {
        if (CUSTOM_CA_CERTIFICATE_LIST_PATH.trim().isEmpty()) {
            return (SSLSocketFactory) SSLSocketFactory.getDefault();
        }

        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Path certificateListPath = Paths.get(CUSTOM_CA_CERTIFICATE_LIST_PATH);
        if (!Files.exists(certificateListPath)) {
            throw new IOException(
                    "Custom CA certificate list not found: " + CUSTOM_CA_CERTIFICATE_LIST_PATH);
        }

        System.out.println("Loading custom certificates from " + CUSTOM_CA_CERTIFICATE_LIST_PATH + ".");

        List<String> lines = Files.readAllLines(certificateListPath, StandardCharsets.UTF_8);
        StringBuilder normalizedCertificates = new StringBuilder();
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            normalizedCertificates.append(trimmed).append('\n');
        }

        byte[] rawCertificates = normalizedCertificates.toString().getBytes(StandardCharsets.UTF_8);
        if (rawCertificates.length == 0) {
            throw new IOException("Custom CA certificate list is empty: "
                    + CUSTOM_CA_CERTIFICATE_LIST_PATH);
        }

        int index = 0;
        try (InputStream certStream = new ByteArrayInputStream(rawCertificates)) {
            Collection<?> certificates = certificateFactory.generateCertificates(certStream);
            for (Object certificate : certificates) {
                if (certificate instanceof X509Certificate) {
                    String alias = "custom-ca-" + index++;
                    keyStore.setCertificateEntry(alias, (X509Certificate) certificate);
                }
            }
        }

        if (index == 0) {
            throw new IOException("No certificates were found inside "
                    + CUSTOM_CA_CERTIFICATE_LIST_PATH);
        }

        System.out.println("Loaded " + index + " custom certificate(s) into the trust store.");

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

    private static final class RuntimeConfig {
        private final boolean useTls;
        private final boolean useProxy;

        private RuntimeConfig(boolean useTls, boolean useProxy) {
            this.useTls = useTls;
            this.useProxy = useProxy;
        }

        static RuntimeConfig fromArgs(String[] args) {
            boolean useTls = DEFAULT_USE_TLS;
            boolean useProxy = DEFAULT_USE_PROXY;

            for (String arg : args) {
                if ("--use-tls".equalsIgnoreCase(arg)) {
                    useTls = true;
                } else if ("--no-tls".equalsIgnoreCase(arg) || "--disable-tls".equalsIgnoreCase(arg)) {
                    useTls = false;
                } else if ("--use-proxy".equalsIgnoreCase(arg)) {
                    useProxy = true;
                } else if ("--no-proxy".equalsIgnoreCase(arg) || "--disable-proxy".equalsIgnoreCase(arg)) {
                    useProxy = false;
                } else if ("--help".equalsIgnoreCase(arg) || "-h".equalsIgnoreCase(arg)) {
                    printUsageAndExit();
                } else {
                    System.err.println("Unrecognized argument: " + arg);
                    printUsageAndExit();
                }
            }

            if (!useTls) {
                System.out.println("TLS disabled via command line; operating in plain TCP mode.");
            }

            if (!useProxy) {
                System.out.println("Proxy disabled via command line; connecting directly to host.");
            }

            return new RuntimeConfig(useTls, useProxy);
        }

        private static void printUsageAndExit() {
            System.out.println("Usage: java -jar iso8583-sender.jar [options]\n" +
                    "Options:\n" +
                    "  --use-tls            Force TLS mode (default).\n" +
                    "  --no-tls             Disable TLS and use plain TCP.\n" +
                    "  --use-proxy          Route the connection through the configured proxy (default).\n" +
                    "  --no-proxy           Disable proxy usage and connect directly.\n" +
                    "  --help               Show this help message.");
            System.exit(0);
        }
    }
}
