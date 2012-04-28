
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * General utilities used by our code
 * 
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 */
public class Utils {

    /**
     * Create a key for use with AES.
     *
     * @param bitLength
     * @param random
     * @return an AES key.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static SecretKey createKeyForAES(
            int bitLength,
            SecureRandom random)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");

        generator.init(256, random);

        return generator.generateKey();
    }

    public static SecretKey createKeyForAES(int bitLength, String key) throws NoSuchAlgorithmException {
        SecretKeySpec skey = new SecretKeySpec(SHA256(key), "AES");
        return skey;
    }

    /**
     * Create an IV suitable for using with AES in CTR mode. <p> The IV will be
     * composed of 4 bytes of message number, 4 bytes of random data, and a
     * counter of 8 bytes.
     *
     * @param messageNumber the number of the message.
     * @param random a source of randomness
     * @return an initialized IvParameterSpec
     */
    public static IvParameterSpec createCtrIvForAES(
            int messageNumber,
            SecureRandom random) {
        byte[] ivBytes = new byte[16];

        // initially randomize

        random.nextBytes(ivBytes);

        // set the message number bytes

        ivBytes[0] = (byte) (messageNumber >> 24);
        ivBytes[1] = (byte) (messageNumber >> 16);
        ivBytes[2] = (byte) (messageNumber >> 8);
        ivBytes[3] = (byte) (messageNumber);
        // Above is the same as:
        // ivBytes[3] = (byte) (messageNumber >> 0);

        // set the counter bytes to 1
        for (int i = 0; i != 7; i++) {
            ivBytes[8 + i] = 0;
        }

        ivBytes[15] = 1;

        return new IvParameterSpec(ivBytes);
    }

    /**
     * Convert a byte array of 8 bit characters into a String.
     *
     * @param bytes the array containing the characters
     * @param length the number of bytes to process
     * @return a String representation of bytes
     */
    public static String toString(
            byte[] bytes,
            int length) {
        char[] chars = new char[length];

        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }

    /**
     * Convert a byte array of 8 bit characters into a String.
     *
     * @param bytes the array containing the characters
     * @return a String representation of bytes
     */
    public static String toString(
            byte[] bytes) {
        return toString(bytes, bytes.length);
    }

    /**
     * Convert the passed in String to a byte array by taking the bottom 8 bits
     * of each character it contains.
     *
     * @param string the string to be converted
     * @return a byte array representation
     */
    public static byte[] toByteArray(
            String string) {
        byte[] bytes = new byte[string.length()];
        char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }

        return bytes;
    }

    /**
     * Input is a string to encrypt.
     *
     * @return a Base64 encoded string of cipher text
     */
    public static String base64Encrypt(String abPlaintext) {
        return base64Encrypt(toByteArray(abPlaintext));
    }

    public static String base64Encrypt(byte[] abPlaintext) {
        BASE64Encoder base64Encoder = new BASE64Encoder();
        try {
            return base64Encoder.encode(abPlaintext);

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Input encrypted String represented in Base64
     *
     * @return a string decrypted in plain text
     */
    public static byte[] base64Decrypt(String base64CipherText) {
        BASE64Decoder base64Decoder = new BASE64Decoder();
        try {
            //return Arrays.toString(base64Decoder.decodeBuffer(base64CipherText));
            return base64Decoder.decodeBuffer(base64CipherText);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] SHA256(String msg) throws NoSuchAlgorithmException {
        // TODO code application logic here
        byte[] output;
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        md.update(msg.getBytes());
        output = md.digest();
        return (output);
    }

    public static String SHA256String(String msg) throws NoSuchAlgorithmException {
        byte[] output;
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        md.update(msg.getBytes());
        output = md.digest();
        return (toHex(output));
    }
    
    private static String digits = "0123456789abcdef";

    /**
     * Return length many bytes of the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    public static String toHex(byte[] data, int length) {
        StringBuilder buf = new StringBuilder();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    /**
     * Return the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }

    public static byte[] hexToByte(String hexString) {
        int len = hexString.length();
        byte[] ba = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            ba[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(hexString.charAt(i + 1), 16));
        }
        return ba;
    }
}
