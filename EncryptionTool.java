
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.security.KeyPair;

public class EncryptionTool extends JFrame implements ActionListener {

    private JTextField messageField;
    private JTextArea outputArea;
    private JButton encryptAesButton, decryptAesButton, encryptRsaButton, decryptRsaButton, selectFileButton, decryptFileButton;
    private SecretKey aesKey;
    private KeyPair rsaKeyPair;

    public EncryptionTool() {
        setTitle("Encryption Tool");
        setSize(400, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new FlowLayout());

        messageField = new JTextField(20);
        outputArea = new JTextArea(10, 30);
        outputArea.setEditable(false);

        encryptAesButton = new JButton("Encrypt AES");
        decryptAesButton = new JButton("Decrypt AES");
        encryptRsaButton = new JButton("Encrypt RSA");
        decryptRsaButton = new JButton("Decrypt RSA");
        selectFileButton = new JButton("Select File to Encrypt");
        decryptFileButton = new JButton("Decrypt File");

        encryptAesButton.addActionListener(this);
        decryptAesButton.addActionListener(this);
        encryptRsaButton.addActionListener(this);
        decryptRsaButton.addActionListener(this);
        selectFileButton.addActionListener(this);
        decryptFileButton.addActionListener(this);

        add(new JLabel("Enter Message: "));
        add(messageField);
        add(encryptAesButton);
        add(decryptAesButton);
        add(encryptRsaButton);
        add(decryptRsaButton);
        add(selectFileButton);
        add(decryptFileButton);  // Added decrypt file button
        add(new JScrollPane(outputArea));

        setVisible(true);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        try {
            if (e.getSource() == encryptAesButton) {
                aesKey = AESEncryption.generateKey();
                String message = messageField.getText();
                String encryptedMessage = AESEncryption.encrypt(message, aesKey);
                outputArea.append("AES Encrypted: " + encryptedMessage + "\n");
                FileUtil.saveKey(aesKey, new File("aesKey.key"));
            } else if (e.getSource() == decryptAesButton) {
                aesKey = FileUtil.loadKey(new File("aesKey.key"));
                String encryptedMessage = messageField.getText();
                String decryptedMessage = AESEncryption.decrypt(encryptedMessage, aesKey);
                outputArea.append("AES Decrypted: " + decryptedMessage + "\n");
            } else if (e.getSource() == encryptRsaButton) {
                rsaKeyPair = RSAEncryption.generateKeyPair();
                String message = messageField.getText();
                String encryptedMessage = RSAEncryption.encrypt(message, rsaKeyPair.getPublic());
                outputArea.append("RSA Encrypted: " + encryptedMessage + "\n");
            } else if (e.getSource() == decryptRsaButton) {
                String encryptedMessage = messageField.getText();
                String decryptedMessage = RSAEncryption.decrypt(encryptedMessage, rsaKeyPair.getPrivate());
                outputArea.append("RSA Decrypted: " + decryptedMessage + "\n");
            } else if (e.getSource() == selectFileButton) {
                JFileChooser fileChooser = new JFileChooser();
                int returnValue = fileChooser.showOpenDialog(this);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File inputFile = fileChooser.getSelectedFile();
                    File outputFile = new File(inputFile.getAbsolutePath() + ".enc");
                    aesKey = FileUtil.loadKey(new File("aesKey.key"));
                    AESEncryption.encryptFile(inputFile, outputFile, aesKey);
                    outputArea.append("File encrypted: " + outputFile.getAbsolutePath() + "\n");
                }
            } else if (e.getSource() == decryptFileButton) {
                JFileChooser fileChooser = new JFileChooser();
                int returnValue = fileChooser.showOpenDialog(this);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File inputFile = fileChooser.getSelectedFile();
                    File outputFile = new File(inputFile.getAbsolutePath().replace(".enc", "_decrypted.txt"));
                    aesKey = FileUtil.loadKey(new File("aesKey.key"));
                    AESEncryption.decryptFile(inputFile, outputFile, aesKey);
                    outputArea.append("File decrypted: " + outputFile.getAbsolutePath() + "\n");
                }
            }
        } catch (Exception ex) {
            outputArea.append("Error: " + ex.getMessage() + "\n");
        }
    }

    public static void main(String[] args) {
        new EncryptionTool();
    }
}
