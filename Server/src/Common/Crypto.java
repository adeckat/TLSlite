package Common;

import static Common.Utilities.byteAppend;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class Crypto {

    private static String CA_CERTIFICATE_FILE = "CAcertificate.pem";

    //Check certificate with CA, return true if it was create by CA, otherwise return false
    public static boolean verifyCertificate(byte[] certificateBytes) {
        X509Certificate cert;
        X509Certificate CAcertificate;
        CAcertificate = loadCertificateFromFile(CA_CERTIFICATE_FILE);
        try {
            InputStream in = new ByteArrayInputStream(certificateBytes);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) certificateFactory.generateCertificate(in);
        } catch (CertificateException e) {
            e.printStackTrace();
            return false;
        }
        try {
            cert.verify(CAcertificate.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    //Get certificate from a byte array
    public static X509Certificate getCertificateFromBytes(byte[] certificateBytes) {
        X509Certificate cert;
        try {
            InputStream in = new ByteArrayInputStream(certificateBytes);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) certificateFactory.generateCertificate(in);
            return cert;
        } catch (CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }

    //Get certificate from file
    private static X509Certificate loadCertificateFromFile(String filePath) {
        CertificateFactory certificateFactory;
        FileInputStream in;
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
            in = new FileInputStream(filePath);
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(in);
            in.close();
            return certificate;
        } catch (CertificateException e) {
            e.printStackTrace();
            return null;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    //Get private key from file
    public static PrivateKey loadPrivateKeyFromFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(filePath);
        byte[] privateKeyByteArray = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey myPrivateKey = keyFactory.generatePrivate(keySpec);
        return myPrivateKey;
    }

    public static byte[] sign(byte[] plainTextBytes, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainTextBytes);
        byte[] signature = privateSignature.sign();
        return signature;
    }

    //Use builtin HMAC functionality
    public static byte[] hkdfExpand(byte[] input, String tag) {
        Key key = new SecretKeySpec(input, 0, input.length, "HmacSHA256");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            Integer one = new Integer(1);
            byte byteOne;
            byteOne = one.byteValue();
            byte[] hkdf = mac.doFinal(byteAppend(tag.getBytes(), new byte[] {byteOne}));
            //Get the first 16 bytes of the result
            return Arrays.copyOfRange(hkdf, 0, 16);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] HMAC_hash(byte[] macKey, byte[] data) {
        Key key = new SecretKeySpec(macKey, 0, macKey.length, "HmacSHA256");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    //Encryption
    public static byte[] encryptAES(byte[] aesKeyBytes, byte[] iv, byte[] inputData) throws InvalidKeyException, IllegalBlockSizeException {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] encryptedData;
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKeySpec keySpec = new SecretKeySpec(aesKeyBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
            encryptedData = cipher.doFinal(inputData);
            return encryptedData;
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    //Decryption
    public static byte[] decryptAES(byte[] aesKeyBytes, byte[] iv, byte[] encryptedData) throws InvalidKeyException, IllegalBlockSizeException {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] plainData;
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKeySpec keySpec = new SecretKeySpec(aesKeyBytes, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
            plainData = cipher.doFinal(encryptedData);
            return plainData;
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }
}

