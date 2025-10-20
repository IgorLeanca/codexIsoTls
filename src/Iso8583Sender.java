import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

public class Iso8583Sender {
    private static final String HOST = "hostigor";
    private static final int PORT = 8056;

    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("Usage: java Iso8583Sender <hex-message>");
            System.exit(1);
        }

        String hexMessage = String.join("", args);
        try {
            byte[] messageBytes = hexToBytes(hexMessage);
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
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(HOST, PORT));

        try (Socket s = socket;
             OutputStream out = new BufferedOutputStream(s.getOutputStream());
             InputStream in = new BufferedInputStream(s.getInputStream())) {

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
