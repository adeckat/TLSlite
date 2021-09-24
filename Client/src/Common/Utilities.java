package Common;

import java.nio.ByteBuffer;

public class Utilities {

    public static byte[] byteAppend(byte[] one, byte[] two) {
        byte[] tmp = new byte[one.length + two.length];
        System.arraycopy(one, 0, tmp, 0, one.length);
        System.arraycopy(two, 0, tmp, one.length, two.length);
        return tmp;
    }

    public static void byteCopy(byte[] src, byte[] dest) {
        byteCopy(src, dest, 0, 0);
    }

    public static void byteCopy(byte[] src, byte[] dest, int from) {
        byteCopy(src, dest, from, 0);
    }

    public static void byteCopy(byte[] src, byte[] dest, int from, int length) {
        if (length > 0 && src.length >= length && dest.length >= length) {
            System.arraycopy(src, from, dest, 0, length);
        }
        else if (src.length > dest.length) {
            System.arraycopy(src, from, dest, 0, dest.length);
        }
        else {
            System.arraycopy(src, 0, dest, from, src.length);
        }
    }

    //Convert int to byte
    public static byte[] convertIntToBytes(int input) {
        ByteBuffer b = ByteBuffer.allocate(4);
        b.putInt(input);
        byte[] result = b.array();
        return result;
    }

    //Convert byte to int
    public static int convertBytesToInt(byte[] bytes) {
        int result = ByteBuffer.wrap(bytes).getInt();
        return result;
    }

    //Compare 2 byte arrays
    public static boolean compareByteArray(byte[] one, byte[] two) {
        if (one.length != two.length) {
            return false;
        }
        for (int i = 0; i < one.length; i++) {
            if (one[i] != two[i]) {
                return false;
            }
        }
        return true;
    }
}
