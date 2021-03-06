
import java.net.*;
import java.io.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.security.*;
import java.security.cert.Certificate;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;

/*
 * The Client that can be run both as a console or a GUI
 */
public class Client  {
	private static final String TRUSTSTOREFILE = "truststore";
	private static final String TRUSTSTOREPASSWORD = "password";

	// for I/O
	private ObjectInputStream sInput;		// to read from the socket
	private ObjectOutputStream sOutput;		// to write on the socket
	private Socket socket = null;

	// if I use a GUI or not
	private ClientGUI cg;

	// the server, the port and the username
	private String server;
	private int port;

	private PublicKey publicKeyServer;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private SecretKey AESKey;
	
	/*
	 *  Constructor called by console mode
	 *  server: the server address
	 *  port: the port number
	 *  username: the username
	 */
	Client(String server, int port) {
		// which calls the common constructor with the GUI set to null
		this(server, port, null);
	}

	/*
	 * Constructor call when used from a GUI
	 * in console mode the ClienGUI parameter is null
	 */
	Client(String server, int port, ClientGUI cg) {
		this.server = server;
		this.port = port;
		// save if we are in GUI mode or not
		this.cg = cg;
	}

	/*
	 * To start the dialog
	 */
	public boolean start(String username, String password) {
		return start(username,password,null);
	}

	public boolean start(String username, String password, String confirmpassword) {
		KeyPair keypair = Util.generateRSAKeys();
		this.privateKey = keypair.getPrivate();
		this.publicKey = keypair.getPublic();

		try {
			socket = new Socket(server, port);
		} catch(Exception e) {
			return false;
		}

		boolean verified;
		/* Creating both Data Stream */
		try {
			sInput  = new ObjectInputStream(socket.getInputStream());
			sOutput = new ObjectOutputStream(socket.getOutputStream());

			// Get certificate from server
			Certificate certificate = (Certificate) sInput.readObject();
			PublicKey publicKey = certificate.getPublicKey();
			this.publicKeyServer = publicKey;

			// Check if certificate is trusted
			verified = verifyCertificate(certificate);
		} catch (Exception e) {
			display("Exception creating new Input/output Streams: " + e);
			return false;
		}

		boolean keepconnection = true;
		if (!verified) { // Certificate is not trusted, prompt if user wants to continue
			String msg = "Certificate is not trusted. your session may not be secure. Do you wish to continue?";
			if (cg != null) {
				String options[] = {"Yes","No (Recommended)"};
				int option = JOptionPane.showOptionDialog(cg, msg,cg.getTitle(),JOptionPane.YES_NO_OPTION,JOptionPane.WARNING_MESSAGE,null,options,options[1]);
				if (option == JOptionPane.NO_OPTION || option == JOptionPane.CLOSED_OPTION) {
					keepconnection = false;
				}
			} else {
				Scanner scanner = new Scanner(System.in);
				System.out.print("WARNING - " + msg + "[Y]es, [N]o (Recommended) => ");
				String input = scanner.next();
				if (input.equalsIgnoreCase("N")) {
					keepconnection = false;
				}
			}
		}

		if (keepconnection) {
			// Send our username to the server this is the only message that we
			// will send as a String. All other messages will be ChatMessage objects
			try {
				// Send public key to server
				sOutput.writeObject(publicKey);

				// Decrypt AES key
				byte[] decryptedKey = Util.decrypt("RSA/ECB/PKCS1Padding", privateKey, (byte[]) sInput.readObject(), null);
				AESKey = new SecretKeySpec(decryptedKey, "AES");

				// Encode username and password in case of special characters
				username = URLEncoder.encode(username, "UTF-8");
				password = URLEncoder.encode(password, "UTF-8");
				String message = username + ":" + password;

				String msg;
				if (confirmpassword != null) {
					confirmpassword = URLEncoder.encode(confirmpassword, "UTF-8");
					message += ":" + confirmpassword;

					sendMessage(ChatMessage.REGISTER, message);
					ChatMessage chatMessage = (ChatMessage) sInput.readObject();
					switch (chatMessage.getType()) {
						case ChatMessage.SUCCESS: {
							msg = "Registration Successful";
							if (cg != null) {
								JOptionPane.showMessageDialog(cg, msg, cg.getTitle(), JOptionPane.INFORMATION_MESSAGE);
								cg.mainDialog();
							} else {
								display("Registration Successful");
							}

							break;
						}

						case ChatMessage.FAIL: {
							msg = "Registration Fail. Username already exists / contains whitespaces or passwords do not match.";
							if (cg != null) {
								JOptionPane.showMessageDialog(cg, msg, cg.getTitle(), JOptionPane.ERROR_MESSAGE);
							} else {
								display("Registration Successful");
							}

							break;
						}
					}
				} else {
					sendMessage(ChatMessage.LOGIN, message);

					ChatMessage chatMessage = (ChatMessage) sInput.readObject();
					switch (chatMessage.getType()) {
						case ChatMessage.SUCCESS: {
							msg = "Connection accepted " + socket.getInetAddress() + ":" + socket.getPort();

							if (cg != null) {
								cg.setClient(this);
								cg.setVisible(false);
								cg.chatDialog();
							}

							display(msg);

							// creates the Thread to listen from the server
							new ListenFromServer(AESKey).start();

							break;
						}

						case ChatMessage.FAIL: {
							msg = "Login Fail";
							if (cg != null) {
								JOptionPane.showMessageDialog(cg, msg, cg.getTitle(), JOptionPane.ERROR_MESSAGE);
							} else {
								display(msg);
							}

							break;
						}
					}
				}
			} catch (Exception e) {
				//display("Exception doing login : " + e);
				disconnect();
				return false;
			}
		} else {
			disconnect();
		}
		
		// success we inform the caller that it worked
		return true;
	}

	/*
	 * To send a message to the console or the GUI
	 */
	private void display(String msg) {
		if (cg == null) {
			System.out.println(msg);      // println in console mode
		} else {
			cg.append(msg + "\n");        // append to the ClientGUI JTextArea (or whatever)
		}
	}

	/*
	 * To send a message to the server
	 */
	void sendMessage(int type, String message) {
		try {
			ChatMessage chatMessage = new ChatMessage();
			chatMessage.setType(type);
			if (message != null) {
				byte[] messageBytes = Util.stringToBytes(message);

				// Generate random IV and encrypt it with server's public key
				IvParameterSpec IV = Util.generateIV();
				byte[] encryptedIV = Util.encryptIV(IV.getIV(),publicKeyServer);
				chatMessage.setEncryptedIV(encryptedIV);

				// Encrypt message with AES
				byte[] cipherText = Util.encrypt("AES/CBC/PKCS5Padding",AESKey,messageBytes,IV);
				chatMessage.setMessage(cipherText);

				// Digital signature
				byte[] salt = Hash.getSalt();
				byte[] hash = Hash.hash(message, salt);
				byte[] digitalSignature = Util.encrypt("RSA/ECB/PKCS1Padding",privateKey,hash,null);
				chatMessage.setDigitalSignature(digitalSignature);
				chatMessage.setSalt(salt);
			}
			
			sOutput.writeObject(chatMessage);
		} catch(Exception e) {
			display("Exception writing to server: " + e);
		}
	}

	/*
	 * When something goes wrong
	 * Close the Input/Output streams and disconnect not much to do in the catch clause
	 */
	private void disconnect() {
		try {
			if (sInput != null) {
				sInput.close();
			}
		} catch (Exception e) {

		} // not much else I can do

		try {
			if (sOutput != null) {
				sOutput.close();
			}
		} catch (Exception e) {

		} // not much else I can do

        try{
			if (socket != null) {
				socket.close();
			}
		} catch (Exception e) {

		} // not much else I can do

		// inform the GUI
		if (cg != null) {
			cg.connectionFailed();
		}
	}
	/*
	 * To start the Client in console mode use one of the following command
	 * > java Client
	 * > java Client username
	 * > java Client username portNumber
	 * > java Client username portNumber serverAddress
	 * at the console prompt
	 * If the portNumber is not specified 1500 is used
	 * If the serverAddress is not specified "localHost" is used
	 * If the username is not specified "Anonymous" is used
	 * > java Client
	 * is equivalent to
	 * > java Client Anonymous 1500 localhost
	 * are eqquivalent
	 *
	 * In console mode, if an error occurs the program simply stops
	 * when a GUI id used, the GUI is informed of the disconnection
	 */
	public static void main(String[] args) {
		// default values
		int portNumber = 1500;
		String serverAddress = "localhost";
		String username = "Anonymous";
		String password = "";

		// depending of the number of arguments provided we fall through
		switch (args.length) {
			// > javac Client username portNumber serverAddr
			case 4:
				serverAddress = args[3];
			// > javac Client username portNumber
			case 3:
				try {
					portNumber = Integer.parseInt(args[2]);
				} catch(Exception e) {
					System.out.println("Invalid port number.");
					System.out.println("Usage is: > java Client [username] [password] [portNumber] [serverAddress]");
					return;
				}
			// > javac Client username
			case 2:
				password = args[1];
			case 1:
				username = args[0];
			// > java Client
			case 0:
				break;
			// invalid number of arguments
			default:
				System.out.println("Usage is: > java Client [username] [password] [portNumber] {serverAddress]");
			return;
		}
		// create the Client object
		Client client = new Client(serverAddress, portNumber);
		// test if we can start the connection to the Server
		// if it failed nothing we can do
		if (!client.start(username,password))
			return;

		// wait for messages from user
		Scanner scan = new Scanner(System.in);
		// loop forever for message from the user
		while (true) {
			System.out.print("> ");
			// read message from user
			String msg = scan.nextLine();
			// logout if message is LOGOUT
			if (msg.equalsIgnoreCase("LOGOUT")) {
				client.sendMessage(ChatMessage.LOGOUT, null);
				// break to do the disconnect
				break;
			} else if (msg.equalsIgnoreCase("WHOISIN")) {
				// message WhoIsIn
				client.sendMessage(ChatMessage.WHOISIN, null);
			} else {
				// default to ordinary message
				client.sendMessage(ChatMessage.MESSAGE, msg);
			}
		}
		scan.close();
		// done disconnect
		client.disconnect();
	}

	/*
	 * a class that waits for the message from the server and append them to the JTextArea
	 * if we have a GUI or simply System.out.println() it in console mode
	 */
	class ListenFromServer extends Thread {
		private Key AESKey;
		
		public ListenFromServer(Key AESKey) {
			this.AESKey = AESKey;
		}

		public void run() {
			while (true) {
				try {
					ChatMessage chatMessage = (ChatMessage) sInput.readObject();
					switch (chatMessage.getType()) {
						case ChatMessage.SHUTDOWN: {
							String msg = "Server is shutting down";
							display(msg);
							if (cg != null) {
								JOptionPane.showMessageDialog(cg,msg,cg.getTitle(),JOptionPane.WARNING_MESSAGE);
							}

							break;
						}

						default: { // Normal message
							String message = getMessage(chatMessage);

							if (message != null) {
								// if console mode print the message and add back the prompt
								if (cg == null) {
									System.out.println(message);
									System.out.print("> ");
								} else {
									cg.append(message);
								}
							}

							break;
						}
					}
				} catch (IOException e) {
					display("Server has close the connection: " + e);
					if (cg != null && cg.isConnected()) {
						cg.connectionFailed();
						cg.mainDialog();
					}

					break;
				} catch (ClassNotFoundException e) {
					// can't happen with a String object but need the catch anyhow
				}
			}
		}

		/*
			Get message from chatMessage object. Will check if from server (Digital Signature).
			If not from server, will return null
		 */
		private String getMessage(ChatMessage chatMessage) {
			String message = null;

			byte[] encryptedMessage = chatMessage.getMessage();
			byte[] encryptedIV = chatMessage.getEncryptedIV();
			IvParameterSpec IV = new IvParameterSpec(Util.decryptIV(encryptedIV,privateKey));
			byte[] digitalSignature = chatMessage.getDigitalSignature();
			byte[] salt = chatMessage.getSalt();

			byte[] messageBytes = Util.decrypt("AES/CBC/PKCS5Padding",AESKey,encryptedMessage,IV);
			byte[] hash = Util.decrypt("RSA/ECB/PKCS1Padding",publicKeyServer,digitalSignature,null);

			message = Util.bytesToString(messageBytes);
			if (!Arrays.equals(hash, Hash.hash(message, salt))) {
				message = null;
			}

			return message;
		}
	}

	/*
		Check if certificate is trusted.
		Tries to find signer in TrustStore
	 */
	private boolean verifyCertificate(Certificate certificate) {
		boolean verify = false;

		try {
			// Load TrustStore
			FileInputStream fileInputStream = new FileInputStream(TRUSTSTOREFILE);
			KeyStore keystore = KeyStore.getInstance("JKS");
			keystore.load(fileInputStream,TRUSTSTOREPASSWORD.toCharArray());
			fileInputStream.close();

			//Get signer
			String issuerDN = ((X509Certificate) certificate).getIssuerDN().getName();

			Enumeration enumeration = keystore.aliases();
			while (enumeration.hasMoreElements()) {
				String alias = (String) enumeration.nextElement();
				if (keystore.isCertificateEntry(alias)) {
					X509Certificate x509Certificate = (X509Certificate) keystore.getCertificate(alias);
					if (x509Certificate.getIssuerDN().getName().equals(issuerDN)) {
						certificate.verify(x509Certificate.getPublicKey()); // Will throw exception if fail
						verify = true;
						break;
					}
				}
			}
		} catch (Exception e) {
			//e.printStackTrace();
		}

		return verify;
	}
}
