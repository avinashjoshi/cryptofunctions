
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * A sample code that does RSA encryption and decryption
 * 
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 */
public class RSASample {

    public static void main(String[] args) throws Exception {
        //Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String fileName = "key";

        PublicKey pubKey = RSA.getPublicKey(fileName);
        PrivateKey privKey = RSA.getPrivateKey(fileName);

        String cipherOld = "jmD1nOW2SMCOFzG8nq8KDzzkt+NftnrNwd0VPSawQz9NxhwBDF5ekIVDAecTVWTPf8eVq4ChEZ29"
                + "fLgmWz1SrzQQ9J80u0xbPNqtPFtb0Dz3z5i1acsVnQztTsrqBd4Qrt1jY78vZM8hokzyidlbb+FP"
                + "jlyp/1tL0VLfY/aT+FA=";

        PrivateKey privKeyOld = RSA.getPrivateKey("avinash");

        String cipherText = RSA.encrypt("avinash was here", pubKey);
        System.out.println(RSA.decrypt(cipherText, privKey));

        System.out.println(RSA.decrypt(cipherOld, privKeyOld));

    }
}
