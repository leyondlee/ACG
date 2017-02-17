import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.security.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.spec.*;
import java.security.cert.Certificate;

/*
 * The server that can be run both as a console application or a GUI
 */
public class Server {
	private static final String KEYSTOREFILENAME = "keystore";
	private static final String KEYSTOREPASSWORD = "password";
	private static final String CERTALIAS = "chatserver_signed";

	// a unique ID for each connection
	private static int uniqueId;
	// an ArrayList to keep the list of the Client
	private ArrayList<ClientThread> al;
	// if I am in a GUI
	private ServerGUI sg;
	// to display time
	private SimpleDateFormat sdf;
	// the port number to listen for connection
	private int port;
	// the boolean that will be turned of to stop the server
	private boolean keepGoing;
	
	private PublicKey publicKey;
	private PrivateKey privateKey;

	private HashMap<String, String> users;

	/*
	 *  server constructor that receive the port to listen to for connection as parameter
	 *  in console
	 */
	public Server(int port) {
		this(port, null);
	}

	public Server(int port, ServerGUI sg) {
		// GUI or not
		this.sg = sg;
		// the port
		this.port = port;
		// to display hh:mm:ss
		sdf = new SimpleDateFormat("HH:mm:ss");
		// ArrayList for the Client list
		al = new ArrayList<ClientThread>();
	}
	
	public void start() {
		keepGoing = true;
		
		KeyPair keypair = getKeyPair();
		this.publicKey = keypair.getPublic();
		this.privateKey = keypair.getPrivate();

		refreshUserList();

		/* create socket server and wait for connection requests */
		try {
			// the socket used by the server
			ServerSocket serverSocket = new ServerSocket(port);

			// infinite loop to wait for connections
			while (keepGoing) {
				// format message saying we are waiting
				display("Server waiting for Clients on port " + port + ".");

				Socket socket = serverSocket.accept();  	// accept connection
				// if I was asked to stop
				if(!keepGoing)
					break;
				ClientThread t = new ClientThread(socket,publicKey,Util.generateAESKey());  // make a thread of it
				al.add(t);									// save it in the ArrayList
				t.start();
			}
			// I was asked to stop
			try {
				serverSocket.close();
				for (int i = 0; i < al.size(); ++i) {
					ClientThread tc = al.get(i);
					try {
					tc.sInput.close();
					tc.sOutput.close();
					tc.socket.close();
					}
					catch(IOException ioE) {
						// not much I can do
					}
				}
			} catch(Exception e) {
				display("Exception closing the server and clients: " + e);
			}
		} catch (IOException e) {
			// something went bad
            String msg = sdf.format(new Date()) + " Exception on new ServerSocket: " + e + "\n";
			display(msg);
		}
	}
    /*
     * For the GUI to stop the server
     */
	protected void stop() {
		keepGoing = false;
		// connect to myself as Client to exit statement
		// Socket socket = serverSocket.accept();

		for (int i = 0; i < al.size(); i++) {
			ClientThread ct = al.get(i);
			ct.keepGoing = false;

			// try to write to the Client if it fails remove it from the list
			if(!ct.writeMsg(ChatMessage.SHUTDOWN,null)) {
				al.remove(i);
				display("Disconnected Client " + ct.username + " removed from list.");
			}
		}

		try {
			new Socket("localhost", port);
		} catch(Exception e) {
			// nothing I can really do
		}
	}
	/*
	 * Display an event (not a message) to the console or the GUI
	 */
	private void display(String msg) {
		String time = sdf.format(new Date()) + " " + msg;
		if(sg == null)
			System.out.println(time);
		else
			sg.appendEvent(time + "\n");
	}
	/*
	 *  to broadcast a message to all Clients
	 */
	private synchronized void broadcast(String message) {
		// add HH:mm:ss and \n to the message
		String time = sdf.format(new Date());
		String messageLf = time + " " + message + "\n";
		// display message on console or GUI
		if (sg == null) {
			System.out.print(messageLf);
		} else {
			sg.appendRoom(messageLf);     // append in the room window
		}

		// we loop in reverse order in case we would have to remove a Client
		// because it has disconnected
		for (int i = al.size(); --i >= 0;) {
			ClientThread ct = al.get(i);
			// try to write to the Client if it fails remove it from the list
			if(!ct.writeMsg(ChatMessage.NONE,messageLf)) {
				al.remove(i);
				display("Disconnected Client " + ct.username + " removed from list.");
			}
		}
	}

	// for a client who logoff using the LOGOUT message
	synchronized void remove(int id) {
		// scan the array list until we found the Id
		for(int i = 0; i < al.size(); ++i) {
			ClientThread ct = al.get(i);
			// found it
			if (ct.id == id) {
				al.remove(i);
				return;
			}
		}
	}

	/*
	 *  To run as a console application just open a console window and:
	 * > java Server
	 * > java Server portNumber
	 * If the port number is not specified 1500 is used
	 */
	public static void main(String[] args) {
		// start server on port 1500 unless a PortNumber is specified
		int portNumber = 1500;
		switch(args.length) {
			case 1:
				try {
					portNumber = Integer.parseInt(args[0]);
				}
				catch(Exception e) {
					System.out.println("Invalid port number.");
					System.out.println("Usage is: > java Server [portNumber]");
					return;
				}
			case 0:
				break;
			default:
				System.out.println("Usage is: > java Server [portNumber]");
				return;

		}
		// create a server object and start it
		Server server = new Server(portNumber);
		server.start();
	}

	/** One instance of this thread will run for each client */
	class ClientThread extends Thread {
		// the socket where to listen/talk
		Socket socket;
		PublicKey publicKeyServer;
		private Key AESKey;
		
		private PublicKey publicKey;
		ObjectInputStream sInput;
		ObjectOutputStream sOutput;
		// my unique id (easier for deconnection)
		int id;
		// the Username of the Client
		String username;
		// the only type of message a will receive
		ChatMessage cm;
		// the date I connect
		String date;
		
		String IP;
		String password;
		boolean keepGoing = false;

		// Constructore
		ClientThread(Socket socket,PublicKey publicKeyServer, Key AESKey) {
			// a unique id
			id = ++uniqueId;
			this.socket = socket;
			this.publicKeyServer = publicKeyServer;
			this.AESKey = AESKey;
			
			this.IP = socket.getRemoteSocketAddress().toString();
			
			/* Creating both Data Stream */
			System.out.println("Thread trying to create Object Input/Output Streams");
			try {
				// create output first
				sOutput = new ObjectOutputStream(socket.getOutputStream());
				sInput  = new ObjectInputStream(socket.getInputStream());

				// Get certificate from KeyStore and send to client
				Certificate certificate = getCertificate();
				sOutput.writeObject(certificate);

				// Read client public key and encrypt AES key with it
				publicKey = (PublicKey) sInput.readObject();
				sOutput.writeObject(Util.encrypt("RSA/ECB/PKCS1Padding",publicKey,AESKey.getEncoded(),null));

				// Initial authentication, client sends credentials
				ChatMessage chatMessage = (ChatMessage) sInput.readObject();
				String message = getMessage(chatMessage);
				if (message != null) {
					String[] parts = message.split(":");
					if (parts.length >= 2) {
						username = URLDecoder.decode(parts[0], "UTF-8");
						password = URLDecoder.decode(parts[1], "UTF-8");

						switch (chatMessage.getType()) {
							case ChatMessage.LOGIN: {
								boolean success = false;

								String value = users.get(username); // If username exists will return string else null
								if (value != null && findClientThread(username) == null) { // Make sure username exists and not logged in currently
									Pattern pattern = Pattern.compile("^\\$(.*)\\$(.*)$"); //Regex to get salt
									Matcher matcher = pattern.matcher(value);

									if (matcher.find()) {
										byte[] salt = Util.hexToBytes(matcher.group(1));
										byte[] passwordhash = Util.hexToBytes(matcher.group(2));
										if (Arrays.equals(Hash.hash(password, salt), passwordhash)) {
											keepGoing = true;
											display(username + " just connected.");
											success = true;
										}
									}
								}

								if (success) {
									writeMsg(ChatMessage.SUCCESS, null);
								} else {
									writeMsg(ChatMessage.FAIL, null);
								}

								break;
							}

							case ChatMessage.REGISTER: {
								String confirmpassword = URLDecoder.decode(parts[2], "UTF-8");

								if (!username.equals("") && !password.equals("") && !username.contains(" ") && password.equals(confirmpassword) && users.get(username) == null) { // Do all checks and make sure username does not exists in database
									byte[] salt = Hash.getSalt();
									byte[] hash = Hash.hash(password, salt);

									String entry = username + ":$" + Util.bytesToHex(salt) + "$" + Util.bytesToHex(hash); // Store similar to shadow file format
									addUser(entry);
									refreshUserList(); // Refresh user HashMap list

									writeMsg(ChatMessage.SUCCESS, null);
								} else {
									writeMsg(ChatMessage.FAIL, null);
								}

								break;
							}
						}
					}
				}
			} catch (IOException e) {
				display("Exception creating new Input/output Streams: " + e);
				return;
			} catch (ClassNotFoundException e) {
				// have to catch ClassNotFoundException
				// but I read a String, I am sure it will work
			}
            date = new Date().toString() + "\n";
		}

		// what will run forever
		public void run() {
			// to loop until LOGOUT
			while (keepGoing) {
				// read a String (which is an object)
				try {
					cm = (ChatMessage) sInput.readObject();
				} catch (IOException e) {
					if (keepGoing) {
						display(username + " Exception reading Streams: " + e);
					}
					break;
				} catch (ClassNotFoundException e2) {
					break;
				}
				
				// the messaage part of the ChatMessage
				String message = getMessage(cm);

				// Switch on the type of message receive
				switch (cm.getType()) {
					case ChatMessage.MESSAGE: {
						if (message != null) {
							Pattern pattern = Pattern.compile("^@(\\S+)\\s(.*)$"); // Regex to see if message is a Private Message
							Matcher matcher = pattern.matcher(message);
							if (matcher.find()) {
								String user = matcher.group(1);
								message = matcher.group(2);
								if (!username.equals(user)) { // Check if trying to pm itself
									ClientThread receiverCT = findClientThread(user);
									if (receiverCT != null) { // Check if receiver is online
										privateMessage(this, receiverCT, message);
									} else {
										writeMsg(ChatMessage.NONE,"User " + user + " is not online.\n");
									}
								} else {
									writeMsg(ChatMessage.NONE,"You cannot private message yourself.\n");
								}
							} else {
								broadcast(username + ": " + message);
							}
						}
						break;
					}

					case ChatMessage.LOGOUT: {
						display(username + " disconnected with a LOGOUT message.");
						keepGoing = false;
						break;
					}

					case ChatMessage.WHOISIN: {
						writeMsg(ChatMessage.NONE,"List of the users connected at " + sdf.format(new Date()) + "\n");
						// scan al the users connected
						for (int i = 0; i < al.size(); ++i) {
							ClientThread ct = al.get(i);
							writeMsg(ChatMessage.NONE,(i + 1) + ") " + ct.username + " (" + ct.IP.substring(1) + ") since " + ct.date);
						}
						break;
					}
				}
			}
			// remove myself from the arrayList containing the list of the
			// connected Clients
			remove(id);
			close();
		}

		// try to close everything
		private void close() {
			// try to close the connection
			try {
				if (sOutput != null) {
					sOutput.close();
				}
			} catch(Exception e) {

			}

			try {
				if (sInput != null) {
					sInput.close();
				}
			} catch(Exception e) {

			};

			try {
				if (socket != null) {
					socket.close();
				}
			} catch (Exception e) {

			};
		}

		/*
		 * Write a String to the Client output stream
		 */
		private boolean writeMsg(int type, String msg) {
			// if Client is still connected send the message to it
			if(!socket.isConnected()) {
				close();
				return false;
			}

			// write the message to the stream
			try {
				ChatMessage chatMessage;
				if (msg != null) {
					byte[] messageBytes = Util.stringToBytes(msg);

					// Create Digital Signature
					byte[] salt = Hash.getSalt();
					byte[] hash = Hash.hash(msg, salt);
					byte[] digitalSignature = Util.encrypt("RSA/ECB/PKCS1Padding", privateKey, hash, null);

					// Encrypt message with random IV
					IvParameterSpec IV = Util.generateIV();
					byte[] encryptedIV = Util.encryptIV(IV.getIV(), publicKey);
					byte[] encryptedMessage = Util.encrypt("AES/CBC/PKCS5Padding", AESKey, messageBytes, IV);

					chatMessage = new ChatMessage(type, encryptedMessage, encryptedIV, digitalSignature, salt);
				} else {
					chatMessage = new ChatMessage();
					chatMessage.setType(type);
				}

				sOutput.writeObject(chatMessage);
			} catch (IOException e) {
				// if an error occurs, do not abort just inform the user
				display("Error sending message to " + username);
				display(e.toString());
			}

			return true;
		}

		/*
			Decrypt and verify that message is from sending client
			If check fail will return null, else will return decrypted message
		 */
		private String getMessage(ChatMessage chatMessage) {
			String message = null;
			byte[] messageBytes = chatMessage.getMessage();
			if (messageBytes != null) {
				byte[] digitalSignature = chatMessage.getDigitalSignature();
				byte[] salt = chatMessage.getSalt();
				byte[] hash = Util.decrypt("RSA/ECB/PKCS1Padding",publicKey,digitalSignature,null);
				try {
					byte[] encryptedIV = chatMessage.getEncryptedIV();
					IvParameterSpec IV = new IvParameterSpec(Util.decryptIV(encryptedIV,privateKey));
					byte[] decryptedText = Util.decrypt("AES/CBC/PKCS5Padding",AESKey,messageBytes,IV);

					if (Arrays.equals(hash, Hash.hash(Util.bytesToString(decryptedText), salt))) {
						message = Util.bytesToString(decryptedText);
					}
				} catch (Exception e) {
					//e.printStackTrace();
				}
			}

			return message;
		}
	}

	// Add new user to "database" aka a file (users.txt)
	private void addUser(String entry) {
		try {
			BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter("users.txt", true));
			bufferedWriter.write(entry);
			bufferedWriter.newLine();
			bufferedWriter.close();
		} catch (Exception e) {
			//e.printStackTrace();
		}
	}

	// Get all users from file and store them in HashMap key: <username>, value: $<salt>$<hashed password>
	private HashMap<String,String> getUsers() {
		HashMap<String,String> users = new HashMap<>();

		try {
			BufferedReader bufferedReader = new BufferedReader(new FileReader("users.txt"));
			String line;
			while ((line = bufferedReader.readLine()) != null) {
				String parts[] = line.split(":");
				String username = parts[0];
				String value = parts[1];

				users.put(username,value);
			}

			bufferedReader.close();
		} catch (Exception e) {
			//e.printStackTrace();
		}

		return users;
	}

	private void refreshUserList() {
		users = getUsers();
	}

	/*
		Handle Private Message
	 */
	private synchronized void privateMessage(ClientThread senderCT, ClientThread receiverCT, String message) {
		String sender = senderCT.username;
		String receiver = receiverCT.username;

		// add HH:mm:ss and \n to the message
		String time = sdf.format(new Date());
		String messageLf = time + " " + sender + " -> " + receiver + ": " + message + "\n";
		// display message on console or GUI
		if (sg == null) {
			System.out.print(messageLf);
		} else {
			sg.appendRoom(messageLf);     // append in the room window
		}

		messageLf = time + " " + sender + " -> You: " + message + "\n";
		receiverCT.writeMsg(ChatMessage.NONE, messageLf);

		messageLf = time + " You -> " + receiver + ": " + message + "\n";
		senderCT.writeMsg(ChatMessage.NONE, messageLf);
	}

	/*
		Will return ClientThread object if username is online, else null
	 */
	private ClientThread findClientThread(String username) {
		ClientThread clientThread = null;

		for (int i = 0; i < al.size(); i++) {
			ClientThread ct = al.get(i);

			if (ct.username.equals(username)) {
				clientThread = ct;
				break;
			}
		}

		return clientThread;
	}

	/*
		Load and return KeyStore. Will return null if fail
	 */
	private KeyStore getKeyStore() {
		KeyStore keyStore = null;
		try {
			FileInputStream fileInputStream = new FileInputStream(KEYSTOREFILENAME);
			keyStore = KeyStore.getInstance("JKS");
			keyStore.load(fileInputStream, KEYSTOREPASSWORD.toCharArray());
			fileInputStream.close();
		} catch (Exception e) {
			//e.printStackTrace();
		}

		return keyStore;
	}

	/*
		Get certificate from KeyStore
	 */
	private Certificate getCertificate() {
		Certificate certificate = null;

		try {
			KeyStore keyStore = getKeyStore();
			if (keyStore != null) {
				certificate = keyStore.getCertificate(CERTALIAS);
			}
		} catch (Exception e) {
			//e.printStackTrace();
		}

		return certificate;
	}

	/*
		Get Private and Public keys from KeyStore
	 */
	private KeyPair getKeyPair() {
		KeyPair keyPair = null;

		KeyStore keyStore = getKeyStore();
		if (keyStore != null) {
			try {
				PublicKey publicKey = getCertificate().getPublicKey();
				PrivateKey privateKey = (PrivateKey) keyStore.getKey(CERTALIAS, KEYSTOREPASSWORD.toCharArray());
				keyPair = new KeyPair(publicKey,privateKey);
			} catch (Exception e) {
				//e.printStackTrace();
			}
		}

		return keyPair;
	}
}
