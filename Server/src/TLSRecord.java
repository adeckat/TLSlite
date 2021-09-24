import Common.Crypto;
import Common.Utilities;

import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;

public class TLSRecord {

    private class MessageType {
        final static int CLIENT_NONCE = 0;
        final static int CERTIFICATE_AND_DH = 1;
        final static int MAC_HANDSHAKE_MSG = 2;
        final static int DATA_TYPE = 3;
    }

    public static byte[] createTLSRecord(byte[] keyMAC, byte[] encryptedAESKey, byte[] iv, byte[] blockData) {
        byte[] encryptedBlockData = null;
        byte[] HMAC = Crypto.HMAC_hash(keyMAC, blockData);
        byte[] tmpEncryptedData = null;
        try {
            //Encrypt data
            tmpEncryptedData = Crypto.encryptAES(encryptedAESKey, iv, blockData);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        //Add HMAC to the end of encrypted data
        byte[] appendedData = Utilities.byteAppend(tmpEncryptedData, HMAC);
        int msgType = MessageType.DATA_TYPE;
        int encryptedPartLength = tmpEncryptedData.length;
        encryptedBlockData = new byte[4 + 4 + encryptedPartLength + HMAC.length];
        Utilities.byteCopy(Utilities.convertIntToBytes(msgType), encryptedBlockData);
        Utilities.byteCopy(Utilities.convertIntToBytes(encryptedPartLength), encryptedBlockData, 4);
        Utilities.byteCopy(appendedData, encryptedBlockData, 8);
        return encryptedBlockData;
    }

    public static byte[] getPlainDataFromTLSRecord(byte[] keyMAC, byte[] encryptedAESKey, byte[] iv, byte[] encryptedBlockData) {
        byte[] tmpMsgType = new byte[4];
        Utilities.byteCopy(encryptedBlockData, tmpMsgType, 0, 4);
        int msgType = Utilities.convertBytesToInt(tmpMsgType);
        if (msgType == MessageType.DATA_TYPE) {
            //The next 4 bytes is encrypted data length without HMAC
            byte[] tmpLength = new byte[4];
            Utilities.byteCopy(encryptedBlockData, tmpLength, 4, 4);
            int blockDataLength = Utilities.convertBytesToInt(tmpLength);
            //block data length next bytes is the encrypted data
            byte[] receivedEncryptedData = new byte[blockDataLength];
            Utilities.byteCopy(encryptedBlockData, receivedEncryptedData, 8, blockDataLength);
            //Remain bytes belongs to HMAC
            byte[] receivedHMAC = new byte[encryptedBlockData.length - 8 - blockDataLength];
            Utilities.byteCopy(encryptedBlockData, receivedHMAC, 8 + blockDataLength);

            //Decryption
            byte[] plainData = null;
            try {
                plainData = Crypto.decryptAES(encryptedAESKey, iv, receivedEncryptedData);
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }

            //Recheck if HMAC is the same
            byte[] HMACVal = Crypto.HMAC_hash(keyMAC, plainData);
            boolean isValidHMAC = Utilities.compareByteArray(HMACVal, receivedHMAC);
            if (isValidHMAC) {
                return plainData;
            }
            else {
                return null;
            }
        }
        else {
            return null;
        }
    }
}