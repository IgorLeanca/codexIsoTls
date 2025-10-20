package net.example.isotls.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.net.SocketTimeoutException;

public final class ResponseReader {

    public enum Strategy {
        EXPECT_HEADER,
        FIXED,
        UNTIL_CLOSE
    }

    private ResponseReader() {
    }

    public static byte[] read(InputStream in, Strategy strategy, int headerLength, ByteOrder headerOrder,
                              boolean headerIncludesPrefix, int fixedBytes) throws IOException {
        switch (strategy) {
            case EXPECT_HEADER:
                return readWithHeader(in, headerLength, headerOrder, headerIncludesPrefix);
            case FIXED:
                return readFixed(in, fixedBytes);
            case UNTIL_CLOSE:
                return readUntilClose(in);
            default:
                throw new IllegalArgumentException("Unsupported read strategy: " + strategy);
        }
    }

    private static byte[] readWithHeader(InputStream in, int headerLength, ByteOrder order, boolean includesPrefix) throws IOException {
        if (headerLength != 2 && headerLength != 4) {
            throw new IllegalArgumentException("Header length must be 2 or 4 bytes");
        }
        byte[] header = readFully(in, headerLength);
        if (header == null) {
            return new byte[0];
        }
        ByteBuffer buffer = ByteBuffer.wrap(header).order(order);
        int length = headerLength == 2 ? buffer.getShort() & 0xFFFF : buffer.getInt();
        if (includesPrefix) {
            length -= headerLength;
        }
        if (length < 0) {
            throw new IOException("Negative payload length from header");
        }
        byte[] payload = readFully(in, length);
        if (payload == null) {
            throw new IOException("Unexpected end of stream when reading payload");
        }
        byte[] combined = new byte[headerLength + payload.length];
        System.arraycopy(header, 0, combined, 0, headerLength);
        System.arraycopy(payload, 0, combined, headerLength, payload.length);
        return combined;
    }

    private static byte[] readFixed(InputStream in, int bytes) throws IOException {
        if (bytes <= 0) {
            throw new IllegalArgumentException("Number of bytes to read must be positive");
        }
        byte[] data = readFully(in, bytes);
        if (data == null) {
            throw new IOException("Unexpected end of stream when reading fixed length");
        }
        return data;
    }

    private static byte[] readUntilClose(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (true) {
            try {
                int read = in.read(buffer);
                if (read == -1) {
                    break;
                }
                out.write(buffer, 0, read);
            } catch (SocketTimeoutException e) {
                break;
            }
        }
        return out.toByteArray();
    }

    private static byte[] readFully(InputStream in, int bytes) throws IOException {
        byte[] buffer = new byte[bytes];
        int offset = 0;
        while (offset < bytes) {
            int read = in.read(buffer, offset, bytes - offset);
            if (read == -1) {
                return null;
            }
            offset += read;
        }
        return buffer;
    }
}
