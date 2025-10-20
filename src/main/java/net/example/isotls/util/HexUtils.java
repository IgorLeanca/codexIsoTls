package net.example.isotls.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class HexUtils {
    private static final Logger LOG = LoggerFactory.getLogger(HexUtils.class);
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    private HexUtils() {
    }

    public static byte[] parseHex(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("Hex input cannot be null");
        }
        String cleaned = hex.replaceAll("\\s+", "");
        if (cleaned.isEmpty()) {
            throw new IllegalArgumentException("Hex input cannot be empty");
        }
        if ((cleaned.length() & 1) != 0) {
            throw new IllegalArgumentException("Hex input must have even length");
        }
        int len = cleaned.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(cleaned.charAt(i), 16);
            int lo = Character.digit(cleaned.charAt(i + 1), 16);
            if (hi == -1 || lo == -1) {
                throw new IllegalArgumentException("Invalid hex character at position " + i);
            }
            data[i / 2] = (byte) ((hi << 4) + lo);
        }
        return data;
    }

    public static String toHex(byte[] data) {
        if (data == null) {
            return "";
        }
        char[] hexChars = new char[data.length * 2];
        for (int j = 0; j < data.length; j++) {
            int v = data[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String asciiPreview(byte[] data) {
        if (data == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(data.length);
        for (byte b : data) {
            int c = b & 0xFF;
            if (c >= 32 && c <= 126) {
                sb.append((char) c);
            } else {
                sb.append('.');
            }
        }
        return sb.toString();
    }

    public static void logHexDump(String prefix, byte[] data) {
        if (LOG.isInfoEnabled()) {
            LOG.info("{}{} ({} bytes)\n{}", prefix, toHex(data), data != null ? data.length : 0, asciiPreview(data));
        }
    }
}
