
import javax.swing.*;

import java.awt.*;
import java.awt.event.*;

/*
 * The Client with its GUI
 */
public class ClientGUI extends JFrame implements ActionListener {
	private static final int LOGIN = 0;
	private static final int REGISTER = 1;

	private static final long serialVersionUID = 1L;
	// will first hold "Username:", later on "Enter message"
	private JLabel label;
	// to hold the Username and later on the messages
	private JTextField tf , hostField, portField;
	// to Logout and get the list of the users
	private JButton logout, whoIsIn;
	// for the chat room
	private JTextArea ta;
	// if it is for connection
	private boolean connected;
	// the Client object
	private Client client;
	// the default port number
	private int port = 1500;
	private String host = "localhost";

	private JPanel northPanel;

	public ClientGUI() {
		mainDialog();
	}

	// called by the Client to append text in the TextArea
	void append(String str) {
		ta.append(str);
		ta.setCaretPosition(ta.getText().length() - 1);
	}
	// called by the GUI is the connection failed
	// we reset our buttons, label, textfield
	void connectionFailed() {
		if (client != null) {
			logout.setEnabled(false);
			whoIsIn.setEnabled(false);
			//label.setHorizontalAlignment(SwingConstants.LEFT);
			// don't react to a <CR> after the username
			tf.removeActionListener(this);
		}
		connected = false;
	}

	/*
	* Button or JTextField clicked
	*/
	public void actionPerformed(ActionEvent e) {
		Object o = e.getSource();

		// if it is the Logout button
		if (o == logout) {
			mainDialog();
			client.sendMessage(ChatMessage.LOGOUT, null);
			return;
		}

		// if it the who is in button
		if (o == whoIsIn) {
			client.sendMessage(ChatMessage.WHOISIN, null);
			return;
		}

		// ok it is coming from the JTextField
		if (connected) {
			// just have to send the message
			String message = tf.getText();
			client.sendMessage(ChatMessage.MESSAGE, message);
			tf.setText("");
			return;
		}
	}

	// to start the whole thing the server
	public static void main(String[] args) {
		new ClientGUI();
		//new ClientGUI("localhost", 1500);
	}

	public void mainDialog() {
		this.connected = false;

		getContentPane().removeAll();
		setTitle("");

		JPanel topPanel = new JPanel(new GridBagLayout());
		topPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		JLabel hostLabel = new JLabel("Server Address: ");
		hostField = new JTextField(host);

		JLabel portLabel = new JLabel("Port: ");
		portField = new JTextField(String.valueOf(port));

		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		gridBagConstraints.insets = new Insets(4, 4, 4, 4);

		setConstraints(gridBagConstraints,0,0, GridBagConstraints.NONE, 0, GridBagConstraints.WEST);
		topPanel.add(hostLabel,gridBagConstraints);

		setConstraints(gridBagConstraints,1,0, GridBagConstraints.HORIZONTAL, 0.75, GridBagConstraints.CENTER);
		topPanel.add(hostField,gridBagConstraints);

		setConstraints(gridBagConstraints,2,0, GridBagConstraints.NONE, 0, GridBagConstraints.CENTER);
		topPanel.add(portLabel,gridBagConstraints);

		setConstraints(gridBagConstraints,3,0, GridBagConstraints.HORIZONTAL, 0.25, GridBagConstraints.CENTER);
		topPanel.add(portField,gridBagConstraints);

		JPanel mainPanel = new JPanel(new GridBagLayout());
		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		setConstraints(gridBagConstraints,0,0, GridBagConstraints.NONE, 0, GridBagConstraints.CENTER);
		JLabel jLabel = new JLabel("Choose an option:");
		mainPanel.add(jLabel,gridBagConstraints);

		setConstraints(gridBagConstraints,0,1, GridBagConstraints.HORIZONTAL, 1.0, GridBagConstraints.CENTER);
		JButton loginButton = new JButton("Login");
		loginButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				saveHostAndPort();
				loginRegisterDialog(LOGIN);
			}
		});
		mainPanel.add(loginButton,gridBagConstraints);

		setConstraints(gridBagConstraints,0,2, GridBagConstraints.HORIZONTAL, 1.0, GridBagConstraints.CENTER);
		JButton registerButton = new JButton("Register");
		registerButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				saveHostAndPort();
				loginRegisterDialog(REGISTER);
			}
		});
		mainPanel.add(registerButton, gridBagConstraints);

		add(topPanel,BorderLayout.NORTH);
		add(mainPanel,BorderLayout.CENTER);
		setDefaultCloseOperation(EXIT_ON_CLOSE);
		setSize(350, 200);
		setLocationRelativeTo(null);
		setVisible(true);
	}

	private void saveHostAndPort() {
		host = hostField.getText();
		try {
			port = Integer.parseInt(portField.getText());
		} catch (Exception e) {
			//e.printStackTrace();
		}
	}

	private void loginRegisterDialog(int type) {
		getContentPane().removeAll();

		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		gridBagConstraints.insets = new Insets(4, 4, 4, 4);

		JPanel mainPanel = new JPanel(new GridBagLayout());
		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		JLabel usernameLabel = new JLabel("Username: ");
		JTextField usernameField = new JTextField();
		JLabel passwordLabel = new JLabel("Password: ");
		JPasswordField passwordField = new JPasswordField();

		setConstraints(gridBagConstraints,0,0, GridBagConstraints.NONE, 0, GridBagConstraints.WEST);
		mainPanel.add(usernameLabel,gridBagConstraints);

		setConstraints(gridBagConstraints,1,0, GridBagConstraints.HORIZONTAL, 1.0, GridBagConstraints.CENTER);
		mainPanel.add(usernameField,gridBagConstraints);

		setConstraints(gridBagConstraints,0,1, GridBagConstraints.NONE, 0, GridBagConstraints.WEST);
		mainPanel.add(passwordLabel,gridBagConstraints);

		setConstraints(gridBagConstraints,1,1, GridBagConstraints.HORIZONTAL, 1.0, GridBagConstraints.CENTER);
		mainPanel.add(passwordField,gridBagConstraints);

		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		buttonPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		JButton jButton = new JButton();

		if (type == LOGIN) {
			setTitle("Login");

			jButton.setText("Login");
			jButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {

					String username = usernameField.getText();
					String password = new String(passwordField.getPassword());

					if (!username.equals("") && !password.equals("")) {
						Client client = new Client(host, port, ClientGUI.this);
						if (!client.start(username, password)) {
							JOptionPane.showMessageDialog(getContentPane(), "Unable to connect to server", getTitle(), JOptionPane.ERROR_MESSAGE);
						}
					} else {
						JOptionPane.showMessageDialog(getContentPane(), "You must enter both username and password", getTitle(), JOptionPane.ERROR_MESSAGE);
					}
				}
			});
		} else {
			setTitle("Registration");

			JLabel confirmPasswordLabel = new JLabel("Confirm Password: ");
			JPasswordField confirmPasswordField = new JPasswordField();

			setConstraints(gridBagConstraints,0,2, GridBagConstraints.NONE, 0, GridBagConstraints.WEST);
			mainPanel.add(confirmPasswordLabel,gridBagConstraints);

			setConstraints(gridBagConstraints,1,2, GridBagConstraints.HORIZONTAL, 1.0, GridBagConstraints.CENTER);
			mainPanel.add(confirmPasswordField,gridBagConstraints);

			jButton.setText("Register");
			jButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					String username = usernameField.getText();
					String password = new String(passwordField.getPassword());
					String confirmpassword = new String(confirmPasswordField.getPassword());

					if (!username.equals("") && !password.equals("") && !confirmpassword.equals("")) {
						Client client = new Client(host, port, ClientGUI.this);
						if (!client.start(username, password, confirmpassword)) {
							JOptionPane.showMessageDialog(getContentPane(), "Unable to connect to server", getTitle(), JOptionPane.ERROR_MESSAGE);
						}
					} else {
						JOptionPane.showMessageDialog(getContentPane(), "You must fill in all fields", getTitle(), JOptionPane.ERROR_MESSAGE);
					}
				}
			});
		}

		buttonPanel.add(jButton);
		JButton cancelButton = new JButton("Cancel");
		cancelButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				mainDialog();
			}
		});
		buttonPanel.add(cancelButton);

		add(mainPanel,BorderLayout.CENTER);
		add(buttonPanel,BorderLayout.SOUTH);
		setSize(350, 200);
		setVisible(true);
		usernameField.requestFocusInWindow();
		getRootPane().setDefaultButton(jButton);
	}

	public void chatDialog() {
		this.connected = true;

		getContentPane().removeAll();
		setTitle("Chat Client");

		// The NorthPanel with:
		northPanel = new JPanel(new GridLayout(2,1));

		// the Label and the TextField
		label = new JLabel("Enter your message below", SwingConstants.CENTER);
		northPanel.add(label);
		tf = new JTextField();
		tf.setBackground(Color.WHITE);
		northPanel.add(tf);
		add(northPanel, BorderLayout.NORTH);

		// The CenterPanel which is the chat room
		ta = new JTextArea("Welcome to the Chat room\n", 80, 80);
		JPanel centerPanel = new JPanel(new GridLayout(1,1));
		centerPanel.add(new JScrollPane(ta));
		ta.setEditable(false);
		add(centerPanel, BorderLayout.CENTER);

		// the 3 buttons
		logout = new JButton("Logout");
		logout.addActionListener(this);
		//logout.setEnabled(false);		// you have to login before being able to logout
		whoIsIn = new JButton("Who is in");
		whoIsIn.addActionListener(this);
		//whoIsIn.setEnabled(false);		// you have to login before being able to Who is in
		tf.addActionListener(this);

		JPanel southPanel = new JPanel();
		southPanel.add(logout);
		southPanel.add(whoIsIn);
		add(southPanel, BorderLayout.SOUTH);

		setDefaultCloseOperation(EXIT_ON_CLOSE);
		setSize(600, 600);
		setLocationRelativeTo(null);
		setVisible(true);
		tf.requestFocus();
	}

	private void setConstraints(GridBagConstraints gridBagConstraints, int gridx, int gridy, int fill, double weightx, int anchor) {
		gridBagConstraints.gridx = gridx;
		gridBagConstraints.gridy = gridy;
		gridBagConstraints.fill = fill;
		gridBagConstraints.weightx = weightx;
		gridBagConstraints.anchor = anchor;
	}

	public boolean isConnected() {
		return connected;
	}

	public void setClient(Client client) {
		this.client = client;
	}
}
