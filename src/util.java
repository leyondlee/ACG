
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

public class util {
	public static KeyPair generateRSAKeys() {
		KeyPair keypair = null;
		
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keypair = keyPairGenerator.genKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return keypair;
	}
	
	public static Key generateAESKey() {
		Key key = null;
		
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(256);
			key = keyGenerator.generateKey();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return key;
	}
	
	public static String bytesToString(byte[] b) {
		String s = null;
		try {
			s = new String(b, StandardCharsets.UTF_8);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return s;
	}
	
	public static byte[] stringToBytes(String s) {
		byte[] b = null;
		try {
			b = s.getBytes(StandardCharsets.UTF_8);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return b;
	}
	
	public static byte[] decrypt(String instance, Key key, byte[] message, AlgorithmParameterSpec params) {
		byte[] cipherText = null;
		
		try {
			Cipher cipher = Cipher.getInstance(instance);
			cipher.init(Cipher.DECRYPT_MODE,key,params);
			cipherText = cipher.doFinal(message);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return cipherText;
	}
	
	public static byte[] encrypt(String instance, Key key, byte[] message, AlgorithmParameterSpec params) {
		byte[] cipherText = null;
		
		try {
			Cipher cipher = Cipher.getInstance(instance);
			cipher.init(Cipher.ENCRYPT_MODE,key,params);
			cipherText = cipher.doFinal(message);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return cipherText;
	}
	
	public static IvParameterSpec generateIV() {
		int length = 128;
		byte[] iv = new byte[length / 8];
		
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(iv);
		
		return new IvParameterSpec(iv);
	}

	public static byte[] encryptIV(byte[] bytes, Key key) {
		bytes = encrypt("RSA/ECB/PKCS1Padding",key,bytes,null);
		return bytes;
	}

	public static byte[] decryptIV(byte[] bytes, Key key) {
		bytes = decrypt("RSA/ECB/PKCS1Padding",key,bytes,null);
		return bytes;
	}

	//Convert from byte array to hex
	public static String bytesToHex(byte buf[]) {
		// Obtain a StringBuffer object
		StringBuffer strbuf = new StringBuffer(buf.length * 2);
		int i;

		for (i = 0; i < buf.length; i++) {
			if (((int) buf[i] & 0xff) < 0x10)
				strbuf.append("0");
			strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
		}
		// Return result string in Hexadecimal format
		return strbuf.toString();
	}

	public static byte[] hexToBytes(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}
}
