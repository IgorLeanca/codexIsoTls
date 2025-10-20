package net.example.isotls.tls;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SNIHostName;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Collections;

public final class TlsSocketFactory {
    private static final String TLS_PROTOCOL = "TLSv1.2";

    private TlsSocketFactory() {
    }

    public static SSLSocket create(String host, int port, String trustStorePath, String trustStorePassword,
                                   String trustStoreType, String keyStorePath, String keyStorePassword,
                                   String keyStoreType) throws IOException, GeneralSecurityException {
        SSLContext context = buildContext(trustStorePath, trustStorePassword, trustStoreType,
                keyStorePath, keyStorePassword, keyStoreType);
        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();
        socket.setKeepAlive(true);
        socket.setSoTimeout(15000);
        socket.connect(new InetSocketAddress(host, port), 5000);
        socket.setEnabledProtocols(new String[]{TLS_PROTOCOL});

        SSLParameters parameters = socket.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setServerNames(Collections.singletonList(new SNIHostName(host)));
        socket.setSSLParameters(parameters);
        socket.startHandshake();
        return socket;
    }

    private static SSLContext buildContext(String trustStorePath, String trustStorePassword, String trustStoreType,
                                           String keyStorePath, String keyStorePassword, String keyStoreType)
            throws IOException, GeneralSecurityException {
        KeyStore trustStore = null;
        if (trustStorePath != null) {
            trustStore = KeyStore.getInstance(trustStoreType != null ? trustStoreType : KeyStore.getDefaultType());
            try (FileInputStream in = new FileInputStream(trustStorePath)) {
                trustStore.load(in, trustStorePassword != null ? trustStorePassword.toCharArray() : null);
            }
        }

        KeyStore keyStore = null;
        if (keyStorePath != null) {
            keyStore = KeyStore.getInstance(keyStoreType != null ? keyStoreType : KeyStore.getDefaultType());
            try (FileInputStream in = new FileInputStream(keyStorePath)) {
                keyStore.load(in, keyStorePassword != null ? keyStorePassword.toCharArray() : null);
            }
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        KeyManagerFactory kmf = null;
        if (keyStore != null) {
            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keyStorePassword != null ? keyStorePassword.toCharArray() : new char[0]);
        }

        SSLContext context = SSLContext.getInstance(TLS_PROTOCOL);
        context.init(kmf != null ? kmf.getKeyManagers() : null, tmf.getTrustManagers(), null);
        return context;
    }
}
