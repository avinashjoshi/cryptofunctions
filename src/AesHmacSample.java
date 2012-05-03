
import java.util.ArrayList;


/**
 * This is a sample code to show how hmac and AES encryption work
 * Logic: CipherText = IV:E_k1{M|HMAC_k2{M}}
 *      Encryption Scheme is AES with CTR mode
 *      HMAC uses HMAC-SHA-256
 * key = "some plain text"
 * keyHash = SHA256(key)
 * k1 = keyHash[0-127] & k2 = keyHash[128-255]
 * 
 * This code uses bouncy castle which can be downloaded from:
 * http://www.bouncycastle.org/latest_releases.html
 * Note: You need to get bcprov-jdk15on-147.jar
 * 
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 */
public class AesHmacSample {

    public static void main(String[] args) throws Exception {
        ArrayList<String> returned = new ArrayList<String>();
        String key = "password_goes_here";
        String cipher;
        returned = AesHmac.doEncryptDecrypt("This text will be encrypted", key, 'E');
        cipher = returned.get(1);
        System.out.println("Cipher Text");
        System.out.println("=======================================================");
        System.out.println(cipher);
        
        cipher = "AAAAASwkDqYAAAAAAAAAAQ==:7ILt9UfRUiuY8fyQlRuItt0+fCSUi6FaJmlfGvWgbKq+j5TH8ng03L5sIeskSwu3qwOdMYWVQ84wfSMV98yWNNlNLTfced9R4KaAcX/WO0Tch3f+7Jf1GpXzpw==";

        returned = AesHmac.doEncryptDecrypt(cipher, key, 'D');
        System.out.println("Plain Text");
        System.out.println("=======================================================");
        System.out.println(returned.get(0) + ": " + returned.get(1));
    }
}
