
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class RSA {

    static String PUBLIC_KEY_HEADER = "-----BEGIN RSA PUBLIC KEY-----\n";
    static String PUBLIC_KEY_FOOTER = "\n-----END RSA PUBLIC KEY-----\n";
    static String PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----\n";
    static String PRIVATE_KEY_FOOTER = "\n-----END RSA PRIVATE KEY-----\n";

    public static void main(String[] args) throws Exception {
        //Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        Cipher cipher = Cipher.getInstance("RSA");

        byte[] input = "this is a test message".getBytes();

        String fileName = "key";

        SecureRandom random = new SecureRandom();

        generatePubPrivPair(1024);

        PublicKey pubKey = getPublicKey(fileName);
        PrivateKey privKey = getPrivateKey(fileName);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        String cipherString = Utils.base64Encrypt(cipherText);
        System.out.println("cipher: " + cipherString);

        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(Utils.base64Decrypt(cipherString));
        System.out.println("plain : " + new String(plainText));

        String cipherOld = "jmD1nOW2SMCOFzG8nq8KDzzkt+NftnrNwd0VPSawQz9NxhwBDF5ekIVDAecTVWTPf8eVq4ChEZ29"
                + "fLgmWz1SrzQQ9J80u0xbPNqtPFtb0Dz3z5i1acsVnQztTsrqBd4Qrt1jY78vZM8hokzyidlbb+FP"
                + "jlyp/1tL0VLfY/aT+FA=";

        PrivateKey privKeyOld = getPrivateKey("avinash");
        cipher.init(Cipher.DECRYPT_MODE, privKeyOld);
        byte[] plainTextOld = cipher.doFinal(Utils.base64Decrypt(cipherOld));
        System.out.println("Old Plain : " + new String(plainTextOld));
    }

    public static void generatePubPrivPair(int keysize) {
        generatePubPrivPair(keysize, "key");
    }

    public static void generatePubPrivPair(int keysize, String fileName) {
        try {
            SecureRandom random = new SecureRandom();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            StringBuilder stringToFile = new StringBuilder();

            generator.initialize(keysize, random);
            KeyPair pair = generator.generateKeyPair();
            Key pubKey = pair.getPublic();
            Key privKey = pair.getPrivate();

            byte[] encodedPub = pubKey.getEncoded();
            byte[] encodedPriv = privKey.getEncoded();

            /*
             * Generating Public key in Base64 Format
             */
            stringToFile.append(PUBLIC_KEY_HEADER);
            stringToFile.append(Utils.base64Encrypt(encodedPub));
            stringToFile.append(PUBLIC_KEY_FOOTER);
            writeKeyToFile(stringToFile.toString(), fileName + ".pub");

            /*
             * Generating Private key in Base64 Format
             */
            stringToFile = new StringBuilder();
            stringToFile.append(PRIVATE_KEY_HEADER);
            stringToFile.append(Utils.base64Encrypt(encodedPriv));
            stringToFile.append(PRIVATE_KEY_FOOTER);
            writeKeyToFile(stringToFile.toString(), fileName + ".priv");

        } catch (NoSuchAlgorithmException ex) {
        }
    }

    public static String encrypt(String inputText, String keyFile) {
        String encryptedText = new String();
        try {
            // Get bytes from input text
            byte[] input = inputText.getBytes();
            PublicKey publicKey = getPublicKey(keyFile);
        } catch (Exception ex) {
        }
        return encryptedText;
    }

    public static boolean writeKeyToFile(String text, String filename) {
        FileOutputStream fos = null;
        boolean returnValue = false;
        try {
            File f = new File(filename);
            fos = new FileOutputStream(f);
            DataOutputStream dos = new DataOutputStream(fos);
            dos.writeBytes(text);
            dos.close();
            returnValue = true;
        } catch (FileNotFoundException ex) {
        } catch (IOException ex) {
        } finally {
            try {
                fos.close();
            } catch (IOException ex) {
            }
        }
        return returnValue;
    }

    public static PublicKey getPublicKey(String filename) {

        PublicKey publicKey = null;
        try {
            File f = new File(filename + ".pub");
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
            byte[] fileBytes = new byte[(int) f.length()];
            dis.readFully(fileBytes);
            dis.close();
            //System.out.println(keyBytes);
            String keyString = new String(fileBytes);
            keyString = keyString.replaceAll(PUBLIC_KEY_HEADER, "");
            keyString = keyString.replaceAll(PUBLIC_KEY_FOOTER, "");
            //System.out.println(keyString);

            byte[] keyBytes = Utils.base64Decrypt(keyString);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(keySpec);

        } catch (InvalidKeySpecException ex) {
        } catch (NoSuchAlgorithmException ex) {
        } catch (IOException ex) {
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String filename) {

        PrivateKey privateKey = null;
        try {
            File f = new File(filename + ".priv");
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
            byte[] fileBytes = new byte[(int) f.length()];
            dis.readFully(fileBytes);
            dis.close();
            //System.out.println(keyBytes);
            String keyString = new String(fileBytes);
            keyString = keyString.replaceAll(PRIVATE_KEY_HEADER, "");
            keyString = keyString.replaceAll(PRIVATE_KEY_FOOTER, "");
            //System.out.println(keyString);

            byte[] keyBytes = Utils.base64Decrypt(keyString);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(keySpec);

        } catch (InvalidKeySpecException ex) {
        } catch (NoSuchAlgorithmException ex) {
        } catch (IOException ex) {
        }
        return privateKey;
    }
}