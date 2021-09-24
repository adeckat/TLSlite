import Common.Crypto;
import Common.DiffieHellman;
import Common.Utilities;
import static Common.Crypto.hkdfExpand;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
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

    //Split file into blocks to send to client
    private final int BLOCK_FILE_SIZE = 4096;

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
    private byte[] clientNonce = new byte[32];
    private byte[] allHandshakeMsgReceived;
    private byte[] allHandshakeMsgSent;
    DataOutputStream dataOutputStream;
    DataInputStream dataInputStream;
    BigInteger myDHPublicKey;
    BigInteger sharedDHKey;

    private Socket clientSocket;

    public TLSHandshake(int partyType) {
        this.utilities = new Utilities();
        this.partyType = partyType;
    }

    public TLSHandshake(Socket clientSocket) {
        try {
            this.clientSocket = clientSocket;
            dataInputStream = new DataInputStream(clientSocket.getInputStream());
            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void run() {
        try {
            while (clientSocket.isConnected()) {
                int len = dataInputStream.readInt();
                byte[] encryptedData = new byte[len];
                dataInputStream.readFully(encryptedData);
                processMsg(encryptedData, clientSocket);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //Generate Diffie Hellman public key
    private void createDHPublicKey() {
        myDHPrivateKey = 4;
        DiffieHellman DH = new DiffieHellman(this.myDHPrivateKey);
        this.myDHPublicKey = DH.generatePublicKey();
    }

    public byte[] createHelloMsg(int partyType) {
        int certificateLength;
        BigInteger DHPublicKey;
        createDHPublicKey();

        DHPublicKey = this.myDHPublicKey;
        int DHPublicKeyLength = DHPublicKey.toByteArray().length;
        PrivateKey RSAPrivateKey = null;
        byte[] certificateBytes = null;

        try {
            if (partyType == PartyType.SERVER) {
                RSAPrivateKey = Crypto.loadPrivateKeyFromFile("serverPrivateKey.der");
                certificateBytes = Files.readAllBytes(Paths.get("CASignedServerCertificate.pem"));
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
        certificateLength = certificateBytes.length;

        try {
            signedDHPublicKey = Crypto.sign(DHPublicKey.toByteArray(), RSAPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        byte[] tmp1 = utilities.byteAppend(utilities.convertIntToBytes(MessageType.CERTIFICATE_AND_DH), utilities.convertIntToBytes(certificateLength));
        byte[] tmp2 = utilities.byteAppend(tmp1, utilities.convertIntToBytes(DHPublicKeyLength));
        byte[] tmp3 = utilities.byteAppend(tmp2, certificateBytes);
        byte[] tmp4 = utilities.byteAppend(tmp3, DHPublicKey.toByteArray());
        byte[] helloMsg = utilities.byteAppend(tmp4, signedDHPublicKey);
        return helloMsg;
    }

    private int processMsg(byte[] inputMsg, Socket clientSocket) {
        this.clientSocket = clientSocket;
        byte[] tmpByteResult = new byte[4];

        //First 4 bytes are Message Type
        utilities.byteCopy(inputMsg, tmpByteResult, 0, 4);
        int msgType = utilities.convertBytesToInt(tmpByteResult);
        if (msgType == MessageType.CLIENT_NONCE) {
            //Store all messages
            storeMsgReceived(inputMsg);
            System.out.println("New length = " + this.allHandshakeMsgReceived.length);
            //If message type is client nonce then generate hello message
            utilities.byteCopy(inputMsg, clientNonce, 4, 32);
            System.out.println("ClientNonce received");

            //Send hello message
            byte[] helloMsg = createHelloMsg(PartyType.SERVER);
            sendData(createHelloMsg(PartyType.SERVER));
            storeMsgSent(helloMsg);
            System.out.println("Sent certificate and DH public key to client");
        }
        if (msgType == MessageType.CERTIFICATE_AND_DH) {
            //Store all messages
            storeMsgReceived(inputMsg);
            System.out.println("New length = " + this.allHandshakeMsgReceived.length);

            //If the message contains certificate and DH public key, the next 4 bytes is the length of server certificate
            utilities.byteCopy(inputMsg, tmpByteResult, 4, 4);
            int certificateLength = utilities.convertBytesToInt(tmpByteResult);

            //The next 4 bytes is the length of DH public key
            utilities.byteCopy(inputMsg, tmpByteResult, 8, 4);
            int DHPublicKeyLength = utilities.convertBytesToInt(tmpByteResult);

            //Server certificate length next bytes is the certificate
            byte[] tmpCertBytes = new byte[certificateLength];
            utilities.byteCopy(inputMsg, tmpCertBytes, 12, certificateLength);
            otherPartyCertificate = Crypto.getCertificateFromBytes(tmpCertBytes);

            //DH public key length next bytes is the DH public key
            byte[] tmpDHPublicKeyBytes = new byte[DHPublicKeyLength];
            utilities.byteCopy(inputMsg, tmpDHPublicKeyBytes, 12 + certificateLength, DHPublicKeyLength);
            otherPartyDHPublicKey = tmpDHPublicKeyBytes;

            //The remain bytes belong to the signed DH public key
            byte[] tmpSignedDHPublicKeyBytes = new byte[inputMsg.length - 12 - certificateLength - DHPublicKeyLength];
            utilities.byteCopy(inputMsg, tmpSignedDHPublicKeyBytes, 12 + certificateLength + DHPublicKeyLength);
            otherPartySignedDHPublicKey = tmpSignedDHPublicKeyBytes;

            System.out.println("Received certificate and DH public key from client");

            //Check if the server certificate was provided by CA
            boolean isValidCertificate;
            isValidCertificate = Crypto.verifyCertificate(tmpCertBytes);
            if (isValidCertificate) {
                System.out.println("Certificate is valid. Start sharing DH key");
                DiffieHellman DH = new DiffieHellman(myDHPrivateKey);
                this.sharedDHKey = DH.generateSharedKey(new BigInteger(otherPartyDHPublicKey));
                System.out.println("Shared DH key = " + sharedDHKey.toString());

                try {
                    makeSecretKeys(clientNonce, sharedDHKey.toByteArray());
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                }

                byte[] MACHandshakeMsg = createMACHandshakeMsg();
                sendData(MACHandshakeMsg);
                storeMsgSent(MACHandshakeMsg);
                return 0;
            }
            else {
                System.out.println("Certificate is invalid");
                closeConnection(clientSocket);
                return -1;
            }
        } else if (msgType == MessageType.MAC_HANDSHAKE_MSG) {
            byte[] HMACBytes = new byte[inputMsg.length - 4];
            utilities.byteCopy(inputMsg, HMACBytes, 4);

            byte[] HMACSentMsg = Crypto.HMAC_hash(clientMAC, this.allHandshakeMsgSent);
            boolean isHMACValid = utilities.compareByteArray(HMACBytes, HMACSentMsg);
            System.out.println("Received HMAC from client " + HMACBytes.toString());
            if (isHMACValid) {
                System.out.println("HMAC is valid, handshake succeeded");
                String filePath = getFilePathToSend();
                System.out.println("Sending file to client: " + filePath);
                sendFileToClient(filePath);
                System.out.println("Sent file successfully");
                return 0;
            }
            else {
                closeConnection(clientSocket);
                System.out.println("HMAC is invalid. Handshake failed");
                return -1;
            }
        } else if (msgType == MessageType.DATA_TYPE) {
            byte[] plainData = TLSRecord.getPlainDataFromTLSRecord(clientMAC, clientEncrypt, clientIV, inputMsg);
            byte[] finished = "Finished".getBytes();
            boolean isCompleted = utilities.compareByteArray(finished, plainData);
            if (isCompleted) {
                System.out.println("Client received file");
            }
        }
        return 0;
    }

    private void sendFileToClient(String filePath) {
        int count;
        byte[] b = new byte[BLOCK_FILE_SIZE];
        File file = new File(filePath);
        byte[] fileName = file.getName().getBytes();
        InputStream in = null;
        OutputStream out = null;
        try {
            out = this.clientSocket.getOutputStream();
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Connecting to server error");
        }
        try {
            in = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.out.println("File is not found " + filePath);
        }
        sendData(TLSRecord.createTLSRecord(serverMAC, serverEncrypt, serverIV, fileName));
        byte[] fileContent = null;
        try {
            fileContent = Files.readAllBytes(Paths.get(filePath));
        } catch (IOException e) {
            e.printStackTrace();
        }
        count = 1;
        if (fileContent.length > BLOCK_FILE_SIZE) {
            while (count * BLOCK_FILE_SIZE < fileContent.length) {
                utilities.byteCopy(fileContent, b, (count-1) * BLOCK_FILE_SIZE, BLOCK_FILE_SIZE);
                count += 1;
                sendData(TLSRecord.createTLSRecord(serverMAC, serverEncrypt, serverIV, b));
            }
            int remainBytes = fileContent.length - (count-1) * BLOCK_FILE_SIZE;
            b = new byte[remainBytes];
            utilities.byteCopy(fileContent, b, (count-1) * BLOCK_FILE_SIZE, remainBytes);
            sendData(TLSRecord.createTLSRecord(serverMAC, serverEncrypt, serverIV, b));
        }
        else {
            sendData(TLSRecord.createTLSRecord(serverMAC, serverEncrypt, serverIV, fileContent));
        }
        byte[] finished = "Finished".getBytes();
        sendData(TLSRecord.createTLSRecord(serverMAC, serverEncrypt, serverIV, finished));
    }

    private String getFilePathToSend() {
        String currentDirectory = System.getProperty("user.dir");
        String strFilePath = null;
        try {
            BufferedReader br = new BufferedReader(new FileReader("FileToSend.txt"));
            strFilePath = br.readLine();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.out.println("File is not found in " + currentDirectory);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return strFilePath;
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
                outputStream = clientSocket.getOutputStream();
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
        byte[] HMACVal = Crypto.HMAC_hash(serverMAC, this.allHandshakeMsgReceived);
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