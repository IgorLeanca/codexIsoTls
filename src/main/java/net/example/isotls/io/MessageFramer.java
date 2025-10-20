package net.example.isotls.io;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class MessageFramer {
    private MessageFramer() {
    }

    public static byte[] frame(byte[] message, byte[] tpdu, int mliLength, ByteOrder order, boolean lengthIncludesPrefix) {
        byte[] payload = concatenate(tpdu, message);
        if (mliLength != 0) {
            if (mliLength != 2 && mliLength != 4) {
                throw new IllegalArgumentException("MLI length must be 0, 2, or 4 bytes");
            }
            int length = payload.length;
            if (lengthIncludesPrefix) {
                length += mliLength;
            }
            ByteBuffer buffer = ByteBuffer.allocate(mliLength + payload.length);
            buffer.order(order);
            if (mliLength == 2) {
                buffer.putShort((short) length);
            } else {
                buffer.putInt(length);
            }
            buffer.put(payload);
            return buffer.array();
        }
        return payload;
    }

    private static byte[] concatenate(byte[] a, byte[] b) {
        byte[] first = a != null ? a : new byte[0];
        byte[] second = b != null ? b : new byte[0];
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}
