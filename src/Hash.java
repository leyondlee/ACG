
import java.security.*;

public class Hash {
	public static byte[] hash(byte[] b, byte[] salt) {
		byte[] result = null;
		
		byte[] msg = new byte[b.length + salt.length];
		System.arraycopy(b, 0, msg, 0, b.length);
		System.arraycopy(salt, 0, msg, b.length, salt.length);
		
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(msg);
			result = md.digest();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return result;
	}
	
	//Random salt
	//https://docs.oracle.com/javase/7/docs/api/java/security/SecureRandom.html
	public static byte[] getSalt() {
		try {
			SecureRandom sr = new SecureRandom();
			byte[] salt = new byte[16];
			sr.nextBytes(salt);

			return salt;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
