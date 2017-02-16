import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

/**
 * Created by Leyond on 10/2/2017.
 */
public class Hash {
    //https://github.com/leyondlee/Hash_Demo/blob/master/src/util/Hash.java
    //https://www.owasp.org/index.php/Hashing_Java
    public static byte[] hash(String s, byte[] salt) {
        byte[] result = null;

		/*
		byte[] msg = new byte[b.length + salt.length];
		System.arraycopy(b, 0, msg, 0, b.length);
		System.arraycopy(salt, 0, msg, b.length, salt.length);

		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(msg);
			result = md.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}*/

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec(s.toCharArray(), salt, 1000, 512);
            SecretKey key = skf.generateSecret(spec);
            result = key.getEncoded();
        } catch (Exception e) {
            //e.printStackTrace();
        }

        return result;
    }

    //Random salt
    //https://docs.oracle.com/javase/7/docs/api/java/security/SecureRandom.html
    public static byte[] getSalt() {
        byte[] salt = null;

        try {
            SecureRandom sr = new SecureRandom();
            salt = new byte[16];
            sr.nextBytes(salt);

            return salt;
        } catch (Exception e) {
            //e.printStackTrace();
        }

        return salt;
    }
}
