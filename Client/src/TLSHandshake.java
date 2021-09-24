import Common.Crypto;
import Common.DiffieHellman;
import Common.Utilities;
import static Common.Crypto.hkdfExpand;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;


public class TLSHandshake extends Thread {

    private class MessageType {
        final static int CLIENT_NONCE = 0;
        final static int CERTIFICATE_AND_DH = 1;
        final static int MAC_HANDSHAKE_MSG = 2;
        final static int DATA_TYPE = 3;
    }

    private class PartyType {
        final static int CLIENT = 1;
        final static int SERVER = 2;
    }

    private Utilities utilities;
    private int partyType;
    private int myDHPrivateKey;
    public static X509Certificate otherPartyCertificate;
    public static byte[] otherPartyDHPublicKey;
    public static byte[] otherPartySignedDHPublicKey;
    private byte[] serverEncrypt;
    private byte[] clientEncrypt;
    private byte[] serverMAC;
    private byte[] clientMAC;
    private byte[] serverIV;
    private byte[] clientIV;
    private byte[] clientNonce;
    private byte[] allHandshakeMsgReceived;
    private byte[] allHandshakeMsgSent;
    DataOutputStream dataOutputStream;
    DataInputStream dataInputStream;
    BigInteger myDHPublicKey;
    BigInteger sharedDHKey;

    private Socket socket;
    private boolean isFileNameBlock = true;
    String fileNameReceived;

    public TLSHandshake(int partyType) {
        this.utilities = new Utilities();
        this.partyType = partyType;
    }

    public TLSHandshake(Socket socket) {
        InputStream in = null;
        try {
            this.socket = socket;
            in = socket.getInputStream();
            dataInputStream = new DataInputStream(in);
            OutputStream out = socket.getOutputStream();
            dataOutputStream = new DataOutputStream(out);
            createClientNonceMsg(socket);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void run() {
        try {
            while (true) {
                int len = dataInputStream.readInt();
                byte[] encryptedData = new byte[len];
                if (len > 0) {
                    dataInputStream.readFully(encryptedData);
                    int result = processMsg(encryptedData, this.socket);
                }
                else {
                    System.out.println("Connecting to server error");
                    closeConnection(socket);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //Generate Diffie Hellman public key
    private void createDHPublicKey() {
        this.myDHPrivateKey = 4;
        DiffieHellman DH = new DiffieHellman(this.myDHPrivateKey);
        this.myDHPublicKey = DH.generatePublicKey();
    }

    //At the beginning, client sends 32 bytes to server. This message has first 4 bytes is MessageType.CLIENT_NONCE
    public void createClientNonceMsg(Socket socket) {
        this.socket = socket;
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        this.clientNonce = nonce;

        byte[] msgTypeBytes = utilities.convertIntToBytes(MessageType.CLIENT_NONCE);
        //Add 32 bytes to the end
        byte[] tmpBytes = utilities.byteAppend(msgTypeBytes, clientNonce);
        sendData(tmpBytes);
        storeMsgSent(tmpBytes);
    }

    public byte[] createHelloMsg(int partyType) {
        byte[] certificateBytes = null;
        try {
            certificateBytes = Files.readAllBytes(Paths.get("CASignedClientCertificate.pem"));
        } catch (IOException e) {
            e.printStackTrace();
        }

        int certificateLength = certificateBytes.length;
        int DHPublicKeyLength = myDHPublicKey.toByteArray().length;
        PrivateKey RSAPrivateKey = null;

        try {
            if (partyType == PartyType.SERVER) {
                RSAPrivateKey = Crypto.loadPrivateKeyFromFile("serverPrivateKey.der");
            }
            else {
                RSAPrivateKey = Crypto.loadPrivateKeyFromFile("clientPrivateKey.der");
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        byte[] signedDHPublicKey = null;
        try {
            signedDHPublicKey = Crypto.sign(myDHPublicKey.toByteArray(), RSAPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        byte[] tmp1 = utilities.byteAppend(utilities.convertIntToBytes(MessageType.CERTIFICATE_AND_DH), utilities.convertIntToBytes(certificateLength));
        byte[] tmp2 = utilities.byteAppend(tmp1, utilities.convertIntToBytes(DHPublicKeyLength));
        byte[] tmp3 = utilities.byteAppend(tmp2, certificateBytes);
        byte[] tmp4 = utilities.byteAppend(tmp3, myDHPublicKey.toByteArray());
        byte[] helloMsg = utilities.byteAppend(tmp4, signedDHPublicKey);
        return helloMsg;
    }

    private int processMsg(byte[] inputMsg, Socket socket) {
        this.socket = socket;
        byte[] tmpByteResult = new byte[4];

        //First 4 bytes are Message Type
        utilities.byteCopy(inputMsg, tmpByteResult, 0, 4);
        int msgType = utilities.convertBytesToInt(tmpByteResult);

        if (msgType == MessageType.CERTIFICATE_AND_DH) {
            //Store all messages
            storeMsgReceived(inputMsg);

            //If the message contains certificate and DH public key, the next 4 bytes is the length of server certificate
            utilities.byteCopy(inputMsg, tmpByteResult, 4, 4);
            int serverCertificateLength = utilities.convertBytesToInt(tmpByteResult);

            //The next 4 bytes is the length of DH public key
            utilities.byteCopy(inputMsg, tmpByteResult, 8, 4);
            int DHPublicKeyLength = utilities.convertBytesToInt(tmpByteResult);

            //Server certificate length next bytes is the certificate
            byte[] tmpCertBytes = new byte[serverCertificateLength];
            utilities.byteCopy(inputMsg, tmpCertBytes, 12, serverCertificateLength);
            otherPartyCertificate = Crypto.getCertificateFromBytes(tmpCertBytes);

            //DH public key length next bytes is the DH public key
            byte[] tmpDHPublicKeyBytes = new byte[DHPublicKeyLength];
            utilities.byteCopy(inputMsg, tmpDHPublicKeyBytes, 12 + serverCertificateLength, DHPublicKeyLength);
            otherPartyDHPublicKey = tmpDHPublicKeyBytes;

            //The remain bytes belong to the signed DH public key
            byte[] tmpSignedDHPublicKeyBytes = new byte[inputMsg.length - 12 - serverCertificateLength - DHPublicKeyLength];
            utilities.byteCopy(inputMsg, tmpSignedDHPublicKeyBytes, 12 + serverCertificateLength + DHPublicKeyLength);
            otherPartySignedDHPublicKey = tmpSignedDHPublicKeyBytes;

            //Check if the server certificate was provided by CA
            boolean isValidCertificate;
            isValidCertificate = Crypto.verifyCertificate(tmpCertBytes);
            if (isValidCertificate) {
                System.out.println("Certificate is valid. Start sharing DH key");
                createDHPublicKey();
                DiffieHellman DH = new DiffieHellman(myDHPrivateKey);
                this.sharedDHKey = DH.generateSharedKey(new BigInteger(otherPartyDHPublicKey));
                System.out.println("Shared DH key = " + sharedDHKey.toString());

                try {
                    makeSecretKeys(clientNonce, sharedDHKey.toByteArray());
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                }

                //Send client certificate and DH public key of client to server
                byte[] helloMsg = createHelloMsg(PartyType.CLIENT);
                sendData(helloMsg);
                System.out.println("Sent certificate and DH public key of client to server");
                storeMsgSent(helloMsg);
                return 0;
            }
            else {
                System.out.println("Certificate is invalid");
                closeConnection(socket);
                return -1;
            }
        } else if (msgType == MessageType.MAC_HANDSHAKE_MSG) {
            storeMsgReceived(inputMsg);
            byte[] HMACBytes = new byte[inputMsg.length - 4];
            utilities.byteCopy(inputMsg, HMACBytes, 4);
            byte[] HMACSentMsg = Crypto.HMAC_hash(serverMAC, this.allHandshakeMsgSent);
            boolean isHMACValid = utilities.compareByteArray(HMACBytes, HMACSentMsg);
            System.out.println("Received HMAC from server " + HMACBytes.toString());
            if (isHMACValid) {
                System.out.println("HMAC is valid");
                sendData(createMACHandshakeMsg());
                return 0;
            }
            else {
                closeConnection(socket);
                System.out.println("HMAC is invalid. Close connection");
                return -1;
            }
        } else if (msgType == MessageType.DATA_TYPE) {
            if (inputMsg == null) {
                return -1;
            }
            byte[] plainData = TLSRecord.getPlainDataFromTLSRecord(serverMAC, serverEncrypt, serverIV, inputMsg);
            if (plainData == null) {
                closeConnection(socket);
                return -1;
            }
            if (isFileNameBlock) {
                try {
                    isFileNameBlock = false;
                    fileNameReceived = new String(plainData, StandardCharsets.UTF_8);
                    System.out.println("File name was sent from server: " + fileNameReceived);
                    Files.deleteIfExists(Paths.get(fileNameReceived));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            else {
                byte[] finished = "Finished".getBytes();
                //If receiving byte Finished then complete receiving file
                boolean isCompleted = utilities.compareByteArray(finished, plainData);
                if (isCompleted) {
                    System.out.println("Received file successfully");
                    sendData(TLSRecord.createTLSRecord(clientMAC, clientEncrypt, clientIV, finished));
                }
                else {
                    try {
                        try (FileOutputStream out = new FileOutputStream(fileNameReceived, true)) {
                            out.write(plainData);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.out.println("Receiving file from server error");
                    }
                }
            }
        }
        return 0;
    }

    private void closeConnection(Socket socket) {
        try {
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void storeMsgSent(byte[] msg) {
        if (this.allHandshakeMsgSent == null) {
            this.allHandshakeMsgSent = msg;
        }
        else {
            this.allHandshakeMsgSent = utilities.byteAppend(this.allHandshakeMsgSent, msg);
        }
    }

    private void storeMsgReceived(byte[] msg) {
        if (this.allHandshakeMsgReceived == null) {
            this.allHandshakeMsgReceived = msg;
        }
        else {
            this.allHandshakeMsgReceived = utilities.byteAppend(this.allHandshakeMsgReceived, msg);
        }
    }

    private void sendData(byte[] encryptedData) {
        try {
            int len = encryptedData.length;
            OutputStream outputStream = null;
            try {
                outputStream = socket.getOutputStream();
            } catch (IOException e) {
                e.printStackTrace();
            }
            DataOutputStream dataOutputStream;
//            DataInputStream dataInputStream;
            dataOutputStream = new DataOutputStream(outputStream);
            try {
                dataOutputStream.writeInt(len);
            } catch (IOException e) {
                e.printStackTrace();
            }
            dataOutputStream.write(encryptedData);
            dataOutputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private byte[] createMACHandshakeMsg() {
        byte[] HMACVal = Crypto.HMAC_hash(clientMAC, this.allHandshakeMsgReceived);
        byte[] tmp = utilities.convertIntToBytes(MessageType.MAC_HANDSHAKE_MSG);
        return utilities.byteAppend(tmp, HMACVal);
    }

    private void makeSecretKeys(byte[] clientNonce, byte[] sharedSecretFromDiffieHellman) throws InvalidKeyException {
        Key key = new SecretKeySpec(clientNonce, 0, clientNonce.length, "HmacSHA256");
        Mac mac;
        byte[] prk;
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            prk = mac.doFinal(sharedSecretFromDiffieHellman);
            serverEncrypt = hkdfExpand(prk, "server encrypt");
            clientEncrypt = hkdfExpand(serverEncrypt, "client encrypt");
            serverMAC = hkdfExpand(clientEncrypt, "server MAC");
            clientMAC = hkdfExpand(serverMAC, "client MAC");
            serverIV = hkdfExpand(clientMAC, "server IV");
            clientIV = hkdfExpand(serverIV, "client IV");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
