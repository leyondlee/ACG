
import java.net.*;
import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;

/*
 * The Client that can be run both as a console or a GUI
 */
public class Client  {

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
		KeyPair keypair = util.generateRSAKeys();
		this.privateKey = keypair.getPrivate();
		this.publicKey = keypair.getPublic();

		try {
			socket = new Socket(server, port);
		} catch(Exception e) {
			return false;
		}

		/* Creating both Data Stream */
		try {
			sInput  = new ObjectInputStream(socket.getInputStream());
			sOutput = new ObjectOutputStream(socket.getOutputStream());
			
			byte[] b = (byte[]) sInput.readObject();
			PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(b));
			this.publicKeyServer = pk;
		} catch (Exception e) {
			display("Exception creating new Input/output Streams: " + e);
			return false;
		}
		
		// Send our username to the server this is the only message that we
		// will send as a String. All other messages will be ChatMessage objects
		try {
			sOutput.writeObject(publicKey);
			
			byte[] decryptedKey = util.decrypt("RSA/ECB/PKCS1Padding",privateKey,(byte[]) sInput.readObject(),null);
			AESKey = new SecretKeySpec(decryptedKey,"AES");

			username = URLEncoder.encode(username,"UTF-8");
			password = URLEncoder.encode(password,"UTF-8");
			String message = username + ":" + password;
			if (confirmpassword != null) {
				confirmpassword = URLEncoder.encode(confirmpassword,"UTF-8");
				message += ":" + confirmpassword;

				sendMessage(ChatMessage.REGISTER,message);
				ChatMessage chatMessage = (ChatMessage) sInput.readObject();
				switch (chatMessage.getType()) {
					case ChatMessage.SUCCESS: {
						if (cg != null) {
							JOptionPane.showMessageDialog(cg,"Registration successful",cg.getTitle(),JOptionPane.INFORMATION_MESSAGE);
							cg.mainDialog();
						}

						break;
					}

					case ChatMessage.FAIL: {
						if (cg != null) {
							JOptionPane.showMessageDialog(cg, "Error: Registration fail", cg.getTitle(), JOptionPane.ERROR_MESSAGE);
						}

						break;
					}
				}
			} else {
				sendMessage(ChatMessage.LOGIN,message);

				ChatMessage chatMessage = (ChatMessage) sInput.readObject();
				switch (chatMessage.getType()) {
					case ChatMessage.SUCCESS: {
						String msg = "Connection accepted " + socket.getInetAddress() + ":" + socket.getPort();

						if (cg != null) {
							cg.setVisible(false);
							cg = new ClientGUI(this);
						}

						display(msg);

						// creates the Thread to listen from the server
						new ListenFromServer(AESKey).start();

						break;
					}

					case ChatMessage.FAIL: {
						if (cg != null) {
							JOptionPane.showMessageDialog(cg, "Error: Login fail", cg.getTitle(), JOptionPane.ERROR_MESSAGE);
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
				byte[] messageBytes = util.stringToBytes(message);

				IvParameterSpec IV = util.generateIV();
				byte[] encryptedIV = util.encryptIV(IV.getIV(),publicKeyServer);
				chatMessage.setEncryptedIV(encryptedIV);

				byte[] cipherText = util.encrypt("AES/CBC/PKCS5Padding",AESKey,messageBytes,IV);
				chatMessage.setMessage(cipherText);

				byte[] salt = Hash.getSalt();
				byte[] hash = Hash.hash(messageBytes, salt);
				byte[] digitalSignature = util.encrypt("RSA/ECB/PKCS1Padding",privateKey,hash,null);
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
			if(sInput != null) sInput.close();
		} catch(Exception e) {

		} // not much else I can do

		try {
			if(sOutput != null) sOutput.close();
		} catch(Exception e) {

		} // not much else I can do

        try{
			if(socket != null) socket.close();
		} catch(Exception e) {

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
		switch(args.length) {
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
		if(!client.start(username,password))
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
			} else if(msg.equalsIgnoreCase("WHOISIN")) {
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
							if (cg != null) {
								JOptionPane.showMessageDialog(cg,"Server has close the connection",cg.getTitle(),JOptionPane.WARNING_MESSAGE);
							}

							break;
						}

						default: {
							byte[] encryptedMessage = chatMessage.getMessage();
							byte[] encryptedIV = chatMessage.getEncryptedIV();
							IvParameterSpec IV = new IvParameterSpec(util.decryptIV(encryptedIV,privateKey));
							byte[] digitalSignature = chatMessage.getDigitalSignature();
							byte[] salt = chatMessage.getSalt();

							byte[] messageBytes = util.decrypt("AES/CBC/PKCS5Padding",AESKey,encryptedMessage,IV);
							byte[] hash = util.decrypt("RSA/ECB/PKCS1Padding",publicKeyServer,digitalSignature,null);

							if (Arrays.equals(hash, Hash.hash(messageBytes, salt))) {
								String msg = util.bytesToString(messageBytes);

								// if console mode print the message and add back the prompt
								if (cg == null) {
									System.out.println(msg);
									System.out.print("> ");
								} else {
									cg.append(msg);
								}
							}

							break;
						}
					}
				} catch (IOException e) {
					display("Server has close the connection: " + e);
					if(cg != null) {
						cg.connectionFailed();
						cg.dispose();
						cg = new ClientGUI();
					}

					break;
				} catch(ClassNotFoundException e) {
					// can't happen with a String object but need the catch anyhow
				}
			}
		}
	}
}
