import java.awt.*; //  provides classes and interfaces for creating and managing graphical user interfaces (GUI) components and containers. It includes classes for windows, buttons, labels and layouts.

import javax.swing.*; // It provides a more advanced set of GUI components, such as frames, panels, buttons and text fields.

import java.awt.event.ActionEvent; // provides classes and interfaces for handling events in AWT (Abstract Window Toolkit) components. 

import java.awt.event.ActionListener;
import java.util.ArrayList; // is a dynamic array implementation that provides resizable arrays for manupilating and accessing array

import java.security.SecureRandom; //  provides classes and interfaces for implementing security-related functionalities. SecureRandom is a class that generates cryptographically strong random numbers.

// These imports are related to handling cryptographic operations. They are part of the Java Cryptography Architecture (JCA) and provide classes for encryption, decryption, key generation, and other cryptographic operations. The java.io.IOException is used for handling input/output exceptions.

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

// These imports are specific to the Java Cryptography Extension (JCE) and provide classes and interfaces for working with cryptographic algorithms, ciphers, and related specifications. PBEKeySpec and PBEParameterSpec are classes used for specifying parameters for password-based encryption algorithms.

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

  /*----------------------------------------------------------------------------------------------- */

// This class is used to create a loading screen

class SplashScreen {
    JFrame frame;
    JLabel image = new JLabel(new ImageIcon("main.jpg"));
    JProgressBar progressBar = new JProgressBar();
    JLabel message = new JLabel(); // A JLabel component that displays a message.

    SplashScreen() {
        createGUI();
        addImage();
        addProgressBar();
        runningPBar(); // increments the value of the progress bar over time.
    }

    /*----------------------------------------------------------------------------------------------- */

    public void createGUI() {
        frame = new JFrame(); // to create a frame
        frame.getContentPane().setLayout(null); // to set the layout of the frame
        frame.setUndecorated(true); // removes the window decorations such as title bar and close button.
        frame.setSize(500, 500); // to set the size of the frame
        frame.setLocationRelativeTo(null); // centers the frame on the screen.

        // frame.getContentPane().setBackground(new Color(0XFF8787)); // to set the
        // background color of the frame

        frame.setIconImage(new ImageIcon("taskbar.jpeg").getImage()); // Set the logo image for the taskbar
        frame.setVisible(true); // makes the frame visible on the screen
    }

    public void addImage() {
        image.setSize(500, 500); // to set the size of the image
        frame.add(image);
    }

    /*----------------------------------------------------------------------------------------------- */

    public void addProgressBar() {
        progressBar.setBounds(120, 331, 210, 40);
        progressBar.setBorderPainted(true); // enables the display of progress border
        progressBar.setStringPainted(true); // enables the display of a string representation of the current progress
                                            // value on the progress bar.
        progressBar.setBackground(Color.black);
        progressBar.setForeground(new Color(0xFFB18F));
        progressBar.setValue(0);
        frame.add(progressBar);
    }

    /*----------------------------------------------------------------------------------------------- */

    public void runningPBar() {
        int i = 0; // Creating an integer variable and initializing it to 0
        while (i <= 100) {
            try {
                Thread.sleep(40); // Pausing execution for 50 milliseconds
                progressBar.setValue(i); // Setting value of Progress Bar
                i++; // increment by 1
                if (i == 100)
                    frame.dispose(); // s called to close the splash screen's frame.
            } catch (Exception e) {
                e.printStackTrace(); // for exception
            }
        }
    }
}

/*----------------------------------------------------------------------------------------------- */

// Linear Probing Implementation
class HashtablePassword implements hashTableMap { // This class is a hash table implementation for storing key-value pairs.
 
    private final int useProbe; // 0 = Linear Probing, 1 = Quadratic Probing
    private Entry[] entries; // The array of entries that holds the key value pair
    private final float loadFactor; // The load factor at which the hash table should be resized.
    private int size, used; // that represents the number of used entries in the hash table, including the
                            // NIL entry.
    private final Entry NIL = new Entry(null, null); // Deleted entries

    // Nested Class that contains key and value objects to store the key-value pair.

    private static class Entry {
        Object key, value;

        Entry(Object k, Object v) {
            key = k;
            value = v;
        }
    }

    // Constructor
    // It creates the entries array with the specified capacity.Sets the loadFactor and useProbe variables accordingly.

    public HashtablePassword(int capacity, float loadFactor, int useProbe) {
        entries = new Entry[capacity];
        this.loadFactor = loadFactor;
        this.useProbe = useProbe;
    }

    /*----------------------------------------------------------------------------------------------- */

    // Complementary functions
    public int hash(Object key) {

        return (key.hashCode() & 0x7FFFFFFF) % entries.length; // This function calculates the hash code for a given key and returns the hash value modulo the size of the entries array. It uses the hashCode() method of the key object and applies a bitwise AND operation with 0x7FFFFFFF to ensure a positive hash value.
    }

    // This function calculates the next probe index based on the current hash value h and the probing index i. It applies modular arithmetic to wrap around to the beginning of the entries array if necessary.

    private int nextProbe(int h, int i) {
        return (h + i) % entries.length; // Linear Probing
    }

    // This method is responsible for resizing the hash table and rehashing the existing entries when the load factor is exceeded.

    private void rehash() {
        Entry[] oldEntries = entries; // It creates a new array oldEntries to store the current entries.
        entries = new Entry[2 * entries.length + 1]; // Resizes the entries array to twice the size plus one.
        for (Entry entry : oldEntries) { // Iterates over the oldEntries and rehashes each entry to find a new position in the resized entries array.
            if (entry == NIL || entry == null)
                continue;
            int h = hash(entry.key);
            for (int x = 0; x < entries.length; x++) {
                int j = nextProbe(h, x);
                if (entries[j] == null) {
                    entries[j] = entry;
                    break;
                }
            }
            used = size; // Updates the used and size variables accordingly.
        }
    }

    @Override
    public int add_Acc(Object Account, Object passwd) {
        if (used > (loadFactor * entries.length))
            rehash();
        int h = hash(Account);
        for (int i = 0; i < entries.length; i++) {
            int j = (h + i) % entries.length;
            Entry entry = entries[j];
            if (entry == null) {
                entries[j] = new Entry(Account, passwd);
                ++size;
                ++used;
                return h;
            }
            if (entry == NIL)
                continue;
            if (entry.key.equals(Account)) {
                Object oldValue = entry.value;
                entries[j].value = passwd;
                return (int) oldValue;
            }
        }
        return h;
    }

    // The class implements the methods declared in the hashTableMap interface 

    @Override
    public Object get_Acc(Object Account) {
        int h = hash(Account);
        for (int i = 0; i < entries.length; i++) {
            int j = nextProbe(h, i);
            Entry entry = entries[j];
            if (entry == null)
                break;
            if (entry == NIL)
                continue;
            if (entry.key.equals(Account))
                return entry.value;
        }
        return null;
    }

    @Override
    public Object remove_Acc(Object Account) {
        int h = hash(Account);
        for (int i = 0; i < entries.length; i++) {
            int j = nextProbe(h, i);
            Entry entry = entries[j];
            if (entry == NIL)
                continue;
            if (entry.key.equals(Account)) {
                Object Value = entry.value;
                entries[j] = NIL;
                size--;
                return Value;
            }
        }
        return null;
    }
}

// Overall, the HashtablePassword class provides a basic implementation of a hash table for storing key-value pairs with collision resolution using either linear or quadratic probing.

/*----------------------------------------------------------------------------------------------- */

// The CryptoUtil class provides a convenient way to encrypt and decrypt text using the "PBEWithMD5AndDES" algorithm with a specified secret key. It utilizes the Cipher class from the javax.crypto package to perform encryption and decryption operations.

class CryptoUtil {

    Cipher ecipher;
    Cipher dcipher;
    // 8-byte Salt, It also defines a byte array salt of length 8, which is used as the salt value in the encryption and decryption process. 
    // Salt is the unique value that add at the end of password
    byte[] salt = {
            (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32,
            (byte) 0x56, (byte) 0x35, (byte) 0xE3, (byte) 0x03
    };
    // Iteration count
    int iterationCount = 19; // The variable iterationCount is set to 19, which determines the number of iterations for the key generation process.

    public CryptoUtil() {

    }

    /**
     *
     * @param secretKey Key used to encrypt data
     * @param plainText Text input to be encrypted
     * @return Returns encrypted text
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.io.UnsupportedEncodingException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     *
     */

    public String encrypt(String secretKey, String plainText)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException,
            NoSuchPaddingException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            UnsupportedEncodingException,
            IllegalBlockSizeException,
            BadPaddingException {
                // The encrypt method takes a secretKey (used for encryption) and a plainText string as input.

        // Key generation for enc and desc
        KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt, iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec); // The KeySpec is then used to generate a SecretKey object using the "PBEWithMD5AndDES" algorithm.
        // Prepare the parameter to the ciphers
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);

        // Enc process
        ecipher = Cipher.getInstance(key.getAlgorithm());
        ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        String charSet = "UTF-8"; // The plainText is converted to a byte array using the UTF-8 character set.
        byte[] in = plainText.getBytes(charSet);
        byte[] out = ecipher.doFinal(in);
        String encStr = new String(Base64.getEncoder().encode(out));
        return encStr;
    }
    // The ecipher is used to encrypt the byte array, producing an encrypted byte array. The encrypted byte array is encoded using Base64 encoding and converted back to a string.

    /**
     * @param secretKey     Key used to decrypt data
     * @param encryptedText encrypted text input to decrypt
     * @return Returns plain text after decryption
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.io.UnsupportedEncodingException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     */
    public String decrypt(String secretKey, String encryptedText)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException,
            NoSuchPaddingException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            UnsupportedEncodingException,
            IllegalBlockSizeException,
            BadPaddingException,
            IOException {
        // Key generation for enc and desc
        KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt, iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
        // Prepare the parameter to the ciphers
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
        // Decryption process; same key will be used for decr
        dcipher = Cipher.getInstance(key.getAlgorithm());
        dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
        byte[] enc = Base64.getDecoder().decode(encryptedText);
        byte[] utf8 = dcipher.doFinal(enc);
        String charSet = "UTF-8";
        String plainStr = new String(utf8, charSet);
        return plainStr;
    }

}

/*----------------------------------------------------------------------------------------------- */

// The PasswordGenerator class provides a simple way to generate random passwords by combining characters from various character sets. The randomness of the passwords is ensured by using the SecureRandom class for generating random indexes.

class PasswordGenerator {
    private static final SecureRandom random = new SecureRandom();
    private static final String caps = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String small_caps = "abcdefghijklmnopqrstuvwxyz";
    private static final String Numeric = "1234567890";
    private static final String special_char = "~!@#$%^&*(_+{}|:_[?]>=<";
    private static final String dic = caps + small_caps + Numeric + special_char;

    public String generatePassword(int len) {
        StringBuilder password = new StringBuilder(); // Inside the loop, it generates a random index between 0 and the length of dic using the random.nextInt() method.

        for (int i = 0; i < len; i++) {
            int index = random.nextInt(dic.length());
            password.append(dic.charAt(index));
        }
        return password.toString(); // After the loop completes, the generated password is converted to a string using the toString() method of StringBuilder.
    }

}

/*----------------------------------------------------------------------------------------------- */

interface hashTableMap {

    Object get_Acc(Object Account);

    int add_Acc(Object Account, Object passwd);

    Object remove_Acc(Object Account);
}

// The PasswordManager class implements the ActionListener interface, which allows it to handle GUI events.The code defines several GUI components and variables to manage the password 

class PasswordManager implements ActionListener {

    // Store password class reference
    HashtablePassword data = new HashtablePassword(15, 0.5F, 0);

    // GUI variables declaration
    JFrame frame;
    JFrame frame2;
    JLabel background;
    Container conn1, conn2;
    JLabel lAcc, lPass;
    JTextArea encryptPasswdArea, genePassArea, searchPassArea;
    JButton PassGeneBtn, PassEncryptBtn, PassStoreBtn, PassSearchBtn, AccAddBtn, PassDeleteBtn;
    JTextField tAcc, tPass;
    JButton addNoteBtn;
    JLabel addNoteLabel;
    JTextArea tNote;
    JButton addNote;
    JFrame conn3;

    ArrayList<String> notes = new ArrayList<>(); // to store the notes in an array list of string type

    @Override
    public void actionPerformed(ActionEvent e) {
    }

    // The FrameGUI and ContainerGUI methods are utility methods to configure the frame and container settings.
    // Frame settings
    public static void FrameGUI(JFrame frame) {
        frame.setVisible(true);
        frame.setLayout(null);
        frame.setLocationRelativeTo(null);
    }

    // container settings
    public static void ContainerGUI(Container conn) {
        conn.setVisible(true);
        conn.setBackground(Color.getHSBColor(20.4f, 10.5f, 12.9f));
        conn.setLayout(null);
    }

    /*----------------------------------------------------------------------------------------------- */
    // The GUIButtonsSetting method is a utility method to configure the appearance of the buttons.
    // buttons settings
    public void GUIButtonsSetting(JButton btn) {
        btn.setBackground(new Color(0XFB2576));
        btn.setForeground(Color.WHITE);
        btn.setBorder(BorderFactory.createLineBorder(Color.BLACK, 3));
        btn.setFocusable(false);
        Cursor crs = new Cursor(Cursor.HAND_CURSOR);
        btn.setCursor(crs);
        Font fn = new Font(Font.SANS_SERIF, Font.BOLD, 15);
        btn.setFont(fn);
    }

    // GUI of Store password
    // The StoringGUI method sets up the GUI for storing passwords. It creates a new frame, adds labels and text fields for account name and password, and sets up a "STORE" button.

    public void StoringGUI() {
        frame2 = new JFrame("Store your passwords");
        frame2.setBounds(1400, 300, 800, 500);
        frame2.setSize(400, 400);
        FrameGUI(frame2);
        conn2 = frame2.getContentPane();
        ContainerGUI(conn2);
        Font fn = new Font(Font.SANS_SERIF, Font.BOLD, 15);

        // Account textFiled and label
        // The textArea method is a utility method used to configure the appearance and behavior of JTextArea components.

        lAcc = new JLabel("ACCOUNT NAME");
        lAcc.setBounds(90, 23, 380, 20);
        lAcc.setFont(fn);
        conn2.add(lAcc);

        tAcc = new JTextField();
        tAcc.setBounds(90, 70, 200, 50);
        tAcc.setFont(fn);
        tAcc.setBorder(BorderFactory.createLineBorder(Color.BLACK, 3));
        tAcc.setForeground(Color.DARK_GRAY);
        conn2.add(tAcc);

        // Account password textField and label
        lPass = new JLabel("ACCOUNT PASSWORD");
        lPass.setBounds(90, 160, 380, 20);
        lPass.setFont(fn);
        conn2.add(lPass);

        tPass = new JTextField();
        tPass.setBounds(90, 200, 200, 50);
        tPass.setFont(fn);
        tPass.setBorder(BorderFactory.createLineBorder(Color.BLACK, 3));
        tPass.setForeground(Color.DARK_GRAY);
        conn2.add(tPass);

        AccAddBtn = new JButton("STORE");
        AccAddBtn.setBounds(120, 290, 150, 50);
        conn2.add(AccAddBtn);
        GUIButtonsSetting(AccAddBtn);
    }

    // for password generator and encryption
    public void textArea(String Pass, JTextArea TA) {
        TA.setText(Pass);
        Font fn = new Font(Font.SANS_SERIF, Font.BOLD, 20);
        TA.setWrapStyleWord(true);
        TA.setLineWrap(true);
        TA.setCaretPosition(0);
        TA.setEditable(false);
        TA.setFont(fn);

    }

    /*----------------------------------------------------------------------------------------------- */

    // GUI of Password Manager
    // The PasswordManager constructor sets up the main GUI for the password manager application. It creates a frame, adds buttons for generating passwords, encrypting/decrypting text, storing/searching/deleting passwords, and adding/retrieving notes.

    PasswordManager() {

        frame = new JFrame("SecureMemo");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 650);
        frame.setResizable(false);
        ImageIcon img = new ImageIcon("background.jpg");
        background = new JLabel("", img, JLabel.CENTER);
        background.setBounds(0, 0, 400, 650);
        background.setVisible(true);
        frame.add(background);

        FrameGUI(frame);

        conn1 = frame.getContentPane();
        ContainerGUI(conn1);

        // Generator buttons settings

        PassGeneBtn = new JButton("Generate Password");
        PassGeneBtn.setBounds(90, 20, 220, 40);
        conn1.add(PassGeneBtn);
        GUIButtonsSetting(PassGeneBtn);

        // Generating password
        PassGeneBtn.addActionListener(e -> { //  This lambda expression takes an ActionEvent object e as a parameter.
            if (e.getSource() == PassGeneBtn) {
                try {
                    int len = Integer.parseInt(JOptionPane.showInputDialog("Enter the password length"));
                    if (len > 4) {
                        // Password generator class reference
                        PasswordGenerator pass = new PasswordGenerator();
                        String passwd = pass.generatePassword(len);
                        genePassArea = new JTextArea(5, 4);
                        textArea(passwd, genePassArea);
                        JOptionPane.showMessageDialog(conn1, new JScrollPane(genePassArea), "Copy your password",
                                JOptionPane.INFORMATION_MESSAGE);

                    } else {
                        JOptionPane.showMessageDialog(conn1, "Password length must be greater than 8!",
                                "Invalid Input Error", JOptionPane.WARNING_MESSAGE);
                    }

                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Write something", "EXIT!", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        // The if statement will execute if the right button is pressed then it will ask to enter the password legth if the password length is less than 4 it will give exception and the inside if block will work. If an exception occurs during the execution of the code (e.g., if the user cancels the input dialog), an error message dialog is displayed.

        // add a encryption button and action
        JButton EncryptBtn = new JButton("Encrypt Text");
        EncryptBtn.setBounds(90, 90, 220, 40);
        conn1.add(EncryptBtn);
        GUIButtonsSetting(EncryptBtn);
        EncryptBtn.addActionListener(e -> {
            if (EncryptBtn == e.getSource()) {
                try {
                    String text = JOptionPane.showInputDialog("Enter the text to encrypt");
                    String secretKey = JOptionPane.showInputDialog("Enter the secret key");
                    if (text.length() > 0 && secretKey.length() > 0) {
                        // password generator class reference
                        CryptoUtil pass1 = new CryptoUtil();
                        String passwd = pass1.encrypt(secretKey, text); // encrypting the text
                        genePassArea = new JTextArea(5, 4); // text area for the encrypted text
                        textArea(passwd, genePassArea); // setting the text area
                        JOptionPane.showMessageDialog(conn1, new JScrollPane(genePassArea), "Copy your password",
                                JOptionPane.INFORMATION_MESSAGE); // showing the encrypted text

                    } else
                        JOptionPane.showMessageDialog(conn1, "Write something", "Invalid Input Error",
                                JOptionPane.WARNING_MESSAGE);

                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Write something", "EXIT!", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // add a decryption button and action
        JButton DecryptBtn = new JButton("Decrypt Text");
        DecryptBtn.setBounds(90, 160, 220, 40);
        conn1.add(DecryptBtn);
        GUIButtonsSetting(DecryptBtn);
        DecryptBtn.addActionListener(e -> {
            if (DecryptBtn == e.getSource()) {
                try {
                    String text = JOptionPane.showInputDialog("Enter the text to decrypt"); // getting the encrypted
                                                                                            // text
                    String secretKey = JOptionPane.showInputDialog("Enter the secret key"); // getting the secret key
                    if (text.length() > 0 && secretKey.length() > 0) // checking if the text and secret key is not empty
                    {
                        // password generator class reference
                        CryptoUtil pass1 = new CryptoUtil(); // creating a object of the CryptoUtil class
                        String passwd = pass1.decrypt(secretKey, text); // decrypting the text
                        genePassArea = new JTextArea(5, 4); // text area for the decrypted text
                        textArea(passwd, genePassArea); // setting the text area
                        JOptionPane.showMessageDialog(conn1, new JScrollPane(genePassArea), "Decrypted text",
                                JOptionPane.INFORMATION_MESSAGE); // showing the decrypted text

                    } else
                        JOptionPane.showMessageDialog(conn1, "Password length must be greater than 8!",
                                "Invalid Input Error", JOptionPane.WARNING_MESSAGE);

                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Write something", "EXIT!", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // storing password using hashtable
        PassStoreBtn = new JButton("Store Password");
        PassStoreBtn.setBounds(90, 230, 220, 40);
        conn1.add(PassStoreBtn);
        GUIButtonsSetting(PassStoreBtn);
        // Store password action
        PassStoreBtn.addActionListener(e -> {
            if (PassStoreBtn == e.getSource()) {
                try {
                    StoringGUI();
                    // action on the Store btn
                    AccAddBtn.addActionListener(e4 -> {
                        if (AccAddBtn == e4.getSource()) {
                            String account_name = tAcc.getText(); // getting the account name
                            String acc_pass = tPass.getText(); // getting the password
                            if (account_name.isEmpty() && acc_pass.isEmpty()) {
                                JOptionPane.showMessageDialog(conn2, "unable to store your password!", "ERROR",
                                        JOptionPane.ERROR_MESSAGE);
                            } else {
                                // calling put method of the hashtablePassword class
                                data.add_Acc(account_name, acc_pass); // adding the account name and password to the
                                                                      // hashtable
                                JOptionPane.showMessageDialog(conn2, "Account added Successfully !");
                                tAcc.setText(null);
                                tPass.setText(null);
                            }
                        }
                    });
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn2, "Write something", "EXIT", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // searching password
        PassSearchBtn = new JButton("Search Password");
        GUIButtonsSetting(PassSearchBtn);
        PassSearchBtn.setBounds(90, 300, 220, 40);
        conn1.add(PassSearchBtn);
        PassSearchBtn.addActionListener(e -> {
            if (PassSearchBtn == e.getSource()) {
                try {
                    String acc_name = JOptionPane.showInputDialog("Enter your Account Name"); // getting the account
                                                                                              // name
                    if (!acc_name.isBlank()) { // checking if the account name is not empty
                        Object pass = data.get_Acc(acc_name.toLowerCase()); // getting the password of the account name
                        if (pass != null) { // checking if the password is not null
                            searchPassArea = new JTextArea(4, 5); // text area for the password
                            textArea(String.valueOf(pass), searchPassArea); // setting the text area
                            JOptionPane.showMessageDialog(conn1, new JScrollPane(searchPassArea), "Copy your password",
                                    JOptionPane.INFORMATION_MESSAGE);
                        } else
                            JOptionPane.showMessageDialog(conn1, "Account not Found!");
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Write something", "EXIT", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // deleting password
        PassDeleteBtn = new JButton("Delete Password");
        GUIButtonsSetting(PassDeleteBtn);
        PassDeleteBtn.setBounds(90, 370, 220, 40);
        conn1.add(PassDeleteBtn);
        PassDeleteBtn.addActionListener(e -> {
            if (PassDeleteBtn == e.getSource()) {
                try {
                    String acc_name = JOptionPane.showInputDialog("Enter the Account Name"); // getting the account name
                    if (!acc_name.isBlank()) {
                        data.remove_Acc(acc_name.toLowerCase()); // removing the account name and password from the
                                                                 // hashtable
                        JOptionPane.showMessageDialog(conn1, "Delete successfully!"); // showing the message
                    } else
                        JOptionPane.showMessageDialog(conn1, "Account not found!", "INFO",
                                JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Write something", "EXIT", JOptionPane.ERROR_MESSAGE);
                }
            }

        });

        addNoteBtn = new JButton("Add Note");
        GUIButtonsSetting(addNoteBtn);
        addNoteBtn.setBounds(90, 440, 220, 40);
        conn1.add(addNoteBtn);
        addNoteBtn.addActionListener(e -> {
            if (addNoteBtn == e.getSource()) {
                try {
                    NoteGUI();
                    // action on the add note btn
                    addNote.addActionListener(e4 -> {
                        if (addNote == e4.getSource()) {
                            String note = tNote.getText(); // getting the note
                            if (note.isEmpty()) {
                                JOptionPane.showMessageDialog(conn3, "unable to store your note!", "ERROR",
                                        JOptionPane.ERROR_MESSAGE);
                            } else {
                                // calling put method of the hashtablePassword class
                                notes.add(note); // adding the note to the arraylist
                                JOptionPane.showMessageDialog(conn3, "Note added Successfully !");
                                conn3.setVisible(false);
                                tNote.setText(null);
                            }
                        }
                    });
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn3, "Write something", "EXIT", JOptionPane.ERROR_MESSAGE);
                }
            }
            
        });

       
        // get all notes
        JButton getNoteBtn = new JButton("Get Note");
        GUIButtonsSetting(getNoteBtn);
        getNoteBtn.setBounds(90, 510, 220, 40);
        conn1.add(getNoteBtn);
        getNoteBtn.addActionListener(e -> {
            if (getNoteBtn == e.getSource()) {
                try {
                    String allNotes = notes.get(notes.size() - 1); // getting the last note added
                    if (allNotes.isEmpty()) { // checking if the note is empty or not
                        JOptionPane.showMessageDialog(conn1, "No note found!", "INFO", JOptionPane.INFORMATION_MESSAGE); // showing
                                                                                                                         // the
                                                                                                                         // message
                    } else {
                        searchPassArea = new JTextArea(4, 5); // text area for the note
                        textArea(allNotes, searchPassArea); // setting the text area
                        JOptionPane.showMessageDialog(conn1, new JScrollPane(searchPassArea), "Get your notes",
                                JOptionPane.INFORMATION_MESSAGE); // showing the message
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Add a note before trying to retrive", "EXIT",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        });

    }
    

    // method for setting the buttons and GUI for adding notes
    //The NoteGUI method is a utility method that sets up the GUI for adding notes. It creates a new frame, adds a label and a text area for adding a note, and sets up an "ADD NOTE" button.

    private void NoteGUI() {

        conn3 = new JFrame("Add Note");
        conn3.setSize(500, 500);
        conn3.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        conn3.setLocationRelativeTo(null);
        conn3.setLayout(null);
        conn3.setVisible(true);
        conn3.setResizable(false);

        // add note label
        addNoteLabel = new JLabel("Add Note");
        addNoteLabel.setBounds(200, 20, 100, 30);
        conn3.add(addNoteLabel);

        // add note text area
        tNote = new JTextArea(10, 10);
        tNote.setBounds(100, 60, 300, 300);
        conn3.add(tNote);

        // add note button
        addNote = new JButton("ADD NOTE");
        GUIButtonsSetting(addNote);
        addNote.setBounds(140, 380, 220, 30);
        conn3.add(addNote);
    }

    /*----------------------------------------------------------------------------------------------- */

    // main method to run the application
    public static void main(String[] args) {
        // loading screen class
        new SplashScreen();
        try {
            new PasswordManager();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}