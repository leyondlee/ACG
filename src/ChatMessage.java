
import java.io.*;

/*
 * This class defines the different type of messages that will be exchanged between the
 * Clients and the Server.
 * When talking from a Java Client to a Java Server a lot easier to pass Java objects, no
 * need to count bytes or to wait for a line feed at the end of the frame
 */
public class ChatMessage implements Serializable {

	protected static final long serialVersionUID = 1112122200L;

	// The different types of message sent by the Client
	// WHOISIN to receive the list of the users connected
	// MESSAGE an ordinary message
	// LOGOUT to disconnect from the Server
	static final int NONE = -1, WHOISIN = 0, MESSAGE = 1, LOGOUT = 2, LOGIN = 3, REGISTER = 4, SUCCESS = 5, FAIL = 6, SHUTDOWN = 7;

	private int type;
	private byte[] message = null;
	private byte[] encryptedIV;
	private byte[] digitalSignature;
	private byte[] salt;

	public ChatMessage() {
	}

	public ChatMessage(int type, byte[] message, byte[] encryptedIV, byte[] digitalSignature, byte[] salt) {
		this.type = type;
		this.message = message;
		this.encryptedIV = encryptedIV;
		this.digitalSignature = digitalSignature;
		this.salt = salt;
	}

	public int getType() {
		return type;
	}

	public void setType(int type) {
		this.type = type;
	}

	public byte[] getMessage() {
		return message;
	}

	public void setMessage(byte[] message) {
		this.message = message;
	}

	public byte[] getEncryptedIV() {
		return encryptedIV;
	}

	public void setEncryptedIV(byte[] encryptedIV) {
		this.encryptedIV = encryptedIV;
	}

	public byte[] getDigitalSignature() {
		return digitalSignature;
	}

	public void setDigitalSignature(byte[] digitalSignature) {
		this.digitalSignature = digitalSignature;
	}

	public byte[] getSalt() {
		return salt;
	}

	public void setSalt(byte[] salt) {
		this.salt = salt;
	}
}
