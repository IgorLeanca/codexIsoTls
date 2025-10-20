package net.example.isotls.cli;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import net.example.isotls.io.MessageFramer;
import net.example.isotls.io.ResponseReader;
import net.example.isotls.tls.TlsSocketFactory;
import net.example.isotls.util.HexUtils;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSocket;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;

public final class IsoTlsClient {
    private static final Logger LOG = LoggerFactory.getLogger(IsoTlsClient.class);
    private static final int DEFAULT_PORT = 3333;
    private static final String DEFAULT_HOST = "hostigor";

    private IsoTlsClient() {
    }

    public static void main(String[] args) {
        Options options = buildOptions();
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse(options, args);
            if (cmd.hasOption("help")) {
                printHelp(options);
                return;
            }
            if (cmd.hasOption("verbose")) {
                enableVerboseLogging();
            }
            execute(cmd);
        } catch (ParseException e) {
            System.err.println("Error parsing arguments: " + e.getMessage());
            printHelp(options);
            System.exit(1);
        } catch (Exception e) {
            LOG.error("Execution failed", e);
            System.err.println("Execution failed: " + e.getMessage());
            System.exit(2);
        }
    }

    private static Options buildOptions() {
        Options options = new Options();
        options.addOption("h", "host", true, "Target host (default hostigor)");
        options.addOption("p", "port", true, "Target port (default 3333)");
        options.addOption(null, "hex", true, "ISO 8583 message as hex string");
        options.addOption(null, "prepend-length", true, "Prepend MLI of 0, 2, or 4 bytes");
        options.addOption(null, "endianness", true, "MLI endianness: big or little (default big)");
        options.addOption(null, "length-includes-prefix", false, "MLI length includes prefix bytes");
        options.addOption(null, "tpdu-hex", true, "Optional TPDU hex to prepend before ISO message");
        options.addOption(null, "message-already-framed", false, "Send bytes exactly as provided in hex");
        options.addOption(null, "read", true, "Read strategy: expect-header, fixed, until-close (default expect-header)");
        options.addOption(null, "read-header-length", true, "Header length (2 or 4) when using expect-header");
        options.addOption(null, "read-header-endianness", true, "Header endianness: big or little (default big)");
        options.addOption(null, "read-header-includes-prefix", false, "Header length includes prefix bytes");
        options.addOption(null, "bytes", true, "Number of bytes to read when using fixed strategy");
        options.addOption(null, "save-response", true, "Path to write response hex");
        options.addOption(null, "truststore", true, "Truststore path");
        options.addOption(null, "truststore-pass", true, "Truststore password");
        options.addOption(null, "truststore-type", true, "Truststore type (JKS or PKCS12)");
        options.addOption(null, "keystore", true, "Keystore path for mTLS");
        options.addOption(null, "keystore-pass", true, "Keystore password");
        options.addOption(null, "keystore-type", true, "Keystore type (JKS or PKCS12)");
        options.addOption(null, "verbose", false, "Enable verbose logging");
        options.addOption(null, "help", false, "Show help");
        return options;
    }

    private static void printHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("java -jar iso-tls.jar", options);
    }

    private static void execute(CommandLine cmd) throws IOException, GeneralSecurityException {
        String host = cmd.getOptionValue("host", DEFAULT_HOST);
        int port = Integer.parseInt(cmd.getOptionValue("port", String.valueOf(DEFAULT_PORT)));
        String hex = cmd.getOptionValue("hex");
        if (hex == null) {
            throw new IllegalArgumentException("--hex option is required");
        }

        byte[] messageBytes = HexUtils.parseHex(hex);
        byte[] tpduBytes = null;
        if (cmd.hasOption("tpdu-hex")) {
            tpduBytes = HexUtils.parseHex(cmd.getOptionValue("tpdu-hex"));
        }

        boolean alreadyFramed = cmd.hasOption("message-already-framed");
        int mliLength = Integer.parseInt(cmd.getOptionValue("prepend-length", "0"));
        ByteOrder mliOrder = parseOrder(cmd.getOptionValue("endianness", "big"));
        boolean mliIncludesPrefix = cmd.hasOption("length-includes-prefix");

        byte[] payload;
        if (alreadyFramed) {
            payload = messageBytes;
        } else {
            payload = MessageFramer.frame(messageBytes, tpduBytes, mliLength, mliOrder, mliIncludesPrefix);
        }

        ResponseReader.Strategy strategy = parseStrategy(cmd.getOptionValue("read", "expect-header"));
        int headerLength = Integer.parseInt(cmd.getOptionValue("read-header-length", "2"));
        ByteOrder headerOrder = parseOrder(cmd.getOptionValue("read-header-endianness", "big"));
        boolean headerIncludesPrefix = cmd.hasOption("read-header-includes-prefix");
        int fixedBytes = Integer.parseInt(cmd.getOptionValue("bytes", "0"));

        if (strategy == ResponseReader.Strategy.FIXED && fixedBytes <= 0) {
            throw new IllegalArgumentException("--bytes must be provided and positive when using fixed read strategy");
        }

        attemptSend(host, port, payload, strategy, headerLength, headerOrder, headerIncludesPrefix,
                fixedBytes, cmd.getOptionValue("save-response"),
                cmd.getOptionValue("truststore"), cmd.getOptionValue("truststore-pass"),
                cmd.getOptionValue("truststore-type"), cmd.getOptionValue("keystore"),
                cmd.getOptionValue("keystore-pass"), cmd.getOptionValue("keystore-type"));
    }

    private static void attemptSend(String host, int port, byte[] payload, ResponseReader.Strategy strategy,
                                    int headerLength, ByteOrder headerOrder, boolean headerIncludesPrefix,
                                    int fixedBytes, String savePath, String trustStore, String trustStorePass,
                                    String trustStoreType, String keyStore, String keyStorePass, String keyStoreType)
            throws IOException, GeneralSecurityException {
        IOException lastException = null;
        for (int attempt = 1; attempt <= 2; attempt++) {
            try (SSLSocket socket = TlsSocketFactory.create(host, port, trustStore, trustStorePass, trustStoreType,
                    keyStore, keyStorePass, keyStoreType)) {
                LOG.info("Connected to {}:{} using TLSv1.2", host, port);
                OutputStream out = socket.getOutputStream();
                out.write(payload);
                out.flush();
                HexUtils.logHexDump("Sent: ", payload);

                byte[] response = ResponseReader.read(socket.getInputStream(), strategy, headerLength,
                        headerOrder, headerIncludesPrefix, fixedBytes);
                HexUtils.logHexDump("Received: ", response);

                if (savePath != null) {
                    try (FileOutputStream fos = new FileOutputStream(savePath)) {
                        fos.write(HexUtils.toHex(response).getBytes());
                    }
                    LOG.info("Response saved to {}", savePath);
                }

                System.out.println("Response HEX: " + HexUtils.toHex(response));
                System.out.println("Response ASCII: " + HexUtils.asciiPreview(response));
                return;
            } catch (IOException e) {
                lastException = e;
                LOG.warn("Attempt {} failed: {}", attempt, e.getMessage());
                if (attempt < 2) {
                    try {
                        Thread.sleep(1000L * attempt);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted during retry", ie);
                    }
                }
            }
        }
        if (lastException != null) {
            throw lastException;
        }
    }

    private static ByteOrder parseOrder(String value) {
        if ("little".equalsIgnoreCase(value)) {
            return ByteOrder.LITTLE_ENDIAN;
        }
        return ByteOrder.BIG_ENDIAN;
    }

    private static ResponseReader.Strategy parseStrategy(String value) {
        if ("fixed".equalsIgnoreCase(value)) {
            return ResponseReader.Strategy.FIXED;
        }
        if ("until-close".equalsIgnoreCase(value)) {
            return ResponseReader.Strategy.UNTIL_CLOSE;
        }
        return ResponseReader.Strategy.EXPECT_HEADER;
    }

    private static void enableVerboseLogging() {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        context.getLogger("ROOT").setLevel(Level.DEBUG);
    }
}
