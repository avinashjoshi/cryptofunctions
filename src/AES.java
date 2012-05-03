
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.ArrayList;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Encoder;

/**
 * This class has all Crypto tools needed by the application.
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 */
public class AES {

    /**
     * This is the main function being called
     *
     * @param receivedText is the text to be encrypted or decrypted
     * @param key is the private key that is used for encryption or decryption
     * @param mode is either 'E' for Encryption or 'D' for decryption
     * @return Returns the encrypted or decrypted string. Returns null if the
     * encryption or decryption is not successful
     * @throws NoSuchAlgorithmException
     * @throws Exception
     */
    public static ArrayList<String> doEncryptDecryptHMAC(String receivedText, String key, char mode) {
        ArrayList<String> returnString = new ArrayList();
        try {
            String keyHash = Utils.SHA256String(key);
            String aesKey = keyHash.substring(0, keyHash.length() / 2);
            String hmacKey = keyHash.substring(keyHash.length() / 2);
            StringBuilder encText = new StringBuilder();

            if (mode == 'E') {
                String hash = AES.genHash(receivedText.getBytes("ASCII"), hmacKey);
                encText.append(receivedText);
                encText.append(hash);
                returnString.add(0, "ENCRYPTED");
                returnString.add(1, encrypt(encText.toString(), aesKey));
            } else if (mode == 'D') {
                String decText = decrypt(receivedText, aesKey);
                String oldHash = decText.substring(decText.length() - 44, decText.length());
                String plainText = decText.substring(0, decText.length() - 44);
                String newHash = AES.genHash(plainText.getBytes("ASCII"), hmacKey);

                if (oldHash.equals(newHash)) {
                    //System.out.println("Hash verified");
                    returnString.add(0, "DECRYPTED");
                    returnString.add(1, plainText);
                } else {
                    //System.out.println("Hash not verified");
                    returnString.add(0, "FAILED");
                    returnString.add(1, "The message has been compromised!");
                }
            }
        } catch (IllegalBlockSizeException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (BadPaddingException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (ShortBufferException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (InvalidAlgorithmParameterException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (NoSuchProviderException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (NoSuchPaddingException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (InvalidKeyException ex) {
            returnString.add(0, "INVALID_KEY");
            returnString.add(1, "Invalid key!");
        } catch (UnsupportedEncodingException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, ex.getMessage());
        } catch (NoSuchAlgorithmException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, ex.getMessage());
        } catch (Exception ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, ex.getMessage());
        }
        return returnString;
    }

    public static ArrayList<String> doEncryptDecrypt(String receivedText, String key, char mode) {
        ArrayList<String> returnString = new ArrayList();
        try {
            String keyHash = Utils.SHA256String(key);
            StringBuilder encText = new StringBuilder();

            if (mode == 'E') {
                encText.append(receivedText);
                returnString.add(0, "ENCRYPTED");
                returnString.add(1, encrypt(encText.toString(), keyHash));
            } else if (mode == 'D') {
                String decText = decrypt(receivedText, keyHash);
                returnString.add(0, "DECRYPTED");
                returnString.add(1, decText);
            }
        } catch (IllegalBlockSizeException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (BadPaddingException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (ShortBufferException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (InvalidAlgorithmParameterException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (NoSuchProviderException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (NoSuchPaddingException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (InvalidKeyException ex) {
            returnString.add(0, "INVALID_KEY");
            returnString.add(1, "Invalid key!");
        } catch (UnsupportedEncodingException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, ex.getMessage());
        } catch (NoSuchAlgorithmException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, ex.getMessage());
        } catch (Exception ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, ex.getMessage());
        }
        return returnString;
    }

    /**
     * This is the main encryption function
     *
     * @param plainText is the plain text that has to be encrypted
     * @param plainKey is the key with which plainText has to be encrypted
     * @return Returns the encrypted String
     * @throws Exception
     */
    private static String encrypt(String plainText, String plainKey) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        SecureRandom random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key cipherKey = Utils.createKeyForAES(256, plainKey);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

        // Encryption step starts here
        ivSpec = new IvParameterSpec(ivSpec.getIV());
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivSpec);

        String finalCipherB64;

        byte[] cipherText = new byte[cipher.getOutputSize(plainText.length())];

        int ctLength = cipher.update(Utils.toByteArray(plainText), 0, plainText.length(), cipherText, 0);

        ctLength += cipher.doFinal(cipherText, ctLength);

        /*
         * We could make plaintext to Hex finalCipherHex =
         * Utils.toHex(ivSpec.getIV()) + ":" + Utils.toHex(cipherText);
         */
        finalCipherB64 = Utils.base64Encrypt(ivSpec.getIV()) + ":" + Utils.base64Encrypt(cipherText);

        return Utils.base64Encrypt(finalCipherB64);
    }

    /**
     * This is the main decryption function
     *
     * @param cipherText is the cipher text that has to be decrypted
     * @param plainKey is the key with which plainText has to be decrypted
     * @return Returns the decrypted String
     * @throws Exception
     */
    private static String decrypt(String cipherText, String plainKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        byte[] plainText = null;
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            IvParameterSpec ivSpec;
            Key cipherKey = Utils.createKeyForAES(256, plainKey);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

            byte[] cipherByte = Utils.base64Decrypt(cipherText);
            cipherText = Utils.toString(cipherByte);
            String split[] = cipherText.split(":");
            ivSpec = new IvParameterSpec(Utils.base64Decrypt(split[0]));
            byte[] cipherBytes = Utils.base64Decrypt(split[1]);

            // decryption step starts here
            cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivSpec);
            int ctLength = cipherBytes.length;
            plainText = new byte[cipher.getOutputSize(ctLength)];
            int ptLength = cipher.update(cipherBytes, 0, ctLength, plainText, 0);
            ptLength += cipher.doFinal(plainText, ptLength);


        } catch (IllegalBlockSizeException ex) {
            throw ex;
        } catch (BadPaddingException ex) {
            throw ex;
        } catch (ShortBufferException ex) {
            throw ex;
        } catch (InvalidKeyException ex) {
            throw ex;
        } catch (InvalidAlgorithmParameterException ex) {
            throw ex;
        } catch (NoSuchAlgorithmException ex) {
            throw ex;
        } catch (NoSuchProviderException ex) {
            throw ex;
        } catch (NoSuchPaddingException ex) {
            throw ex;
        }
        return Utils.toString(plainText);
    }
    private static final String SHA_HMAC_ALGORITHM = "HMACSHA256";
    private static byte[] abDigest = null;
    private static String szResult = null;
    private static String result = null;
    private static Mac shaMac = null;
    private static SecretKeySpec secretKeySpec = null;

    /**
     * Generate hash of the input byte array Current Algorithm is HMACSHA256
     *
     * @param inBuffer Takes the bytes that have to be hashed
     * @param hmacKey Key for calculating HMAC
     * @return Returns the HMAC string
     */
    public static String genHash(byte[] inBuffer, String hmacKey) {
        try {
            result = calcSHAHMAC(inBuffer, hmacKey);
        } catch (SignatureException e) {
            System.err.println("genHash(): Signature Exception");
            result = null;
        }
        return result;
    }

    /**
     * Actual method that generates a hash of the input byte array and returns
     * the Base64 encoded hash string
     *
     * @param inputMsg message whose HMAC has to be calculated
     * @param hmacKey Key
     * @return returns the HMAC as String
     * @throws java.security.SignatureException
     */
    private static String calcSHAHMAC(byte[] inputMsg, String hmacKey)
            throws java.security.SignatureException {
        BASE64Encoder base64Encoder = new BASE64Encoder();
        try {
            shaMac = Mac.getInstance(SHA_HMAC_ALGORITHM);
            secretKeySpec = new SecretKeySpec(hmacKey.getBytes(), SHA_HMAC_ALGORITHM);
            shaMac.init(secretKeySpec);
            abDigest = shaMac.doFinal(inputMsg);
            // convert raw HMAC into Base64
            szResult = base64Encoder.encode(abDigest);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(SHA_HMAC_ALGORITHM + ": no such algorithm!");
            szResult = null;
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key!");
            szResult = null;
        }
        return szResult;
    }
}