/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package trunk;

/**
 *
 * @author chico
 */
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.Mac;
import javax.crypto.SealedObject;

public class Client {
    public static String mode = "";
    public static Mac mac = null;
    static public void main(String[] arg) throws IOException, 
            NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        try {
            
            // Connect to server
            Socket s = new Socket("127.0.0.1",4567);
            byte[] buffer = new byte[48];
            System.out.println("Connected to server...");
            System.out.println("File Name?\n");
            Scanner in = new Scanner(System.in);
            String filename = in.nextLine();
            try ( // Open file to upload
                    FileInputStream file = new FileInputStream(filename); BufferedInputStream BufIn = new BufferedInputStream (file); // Get socket output stream
                    OutputStream sos = s.getOutputStream()) {
                
                // Gets the mode from the server
                InputStream getMode = s.getInputStream();
                getMode.read(buffer);
                String ex = new String(buffer, StandardCharsets.UTF_8);
                mode = ex;
                System.out.println("MODE: " + mode + "\n");
                
                /*
                // Tutorial 6, receiving public key from server
                ObjectInputStream ois = new ObjectInputStream(getMode);
                PublicKey publicKey = (PublicKey)ois.readObject();
                System.out.println("Received Public Key: "+Util.asHex(publicKey.getEncoded()));
                
                // Tutorial 7, receiving signature from server
                byte[] signature = (byte[])ois.readObject();
                if(Util.verifySignature(signature, publicKey))
                {
                System.out.println("Signature is ok!");
                } else
                {
                System.out.println("Signature and public key from server don't match. Server isn't trusted by TA");
                System.exit(-1);
                }*/
                // Tutorial 8
                // Client's private key
                RSAPrivateKey clientPrivKey = Util.getPrivateKeys("client");
                ValidateCertPath validateCertPath = new ValidateCertPath();
                X509Certificate clientCert = ValidateCertPath.getCertFromFile("./client.cer");
                ObjectInputStream ois = new ObjectInputStream(getMode);
                X509Certificate serverCertificate = (X509Certificate) ois.readObject();
                System.out.println("Got server's certificate.\n");
                
                try ( 
                    // Time to send Certificate
                    ObjectOutputStream oos = new ObjectOutputStream(sos)) {
                    oos.writeObject(clientCert);
                    //oos.flush();
                    System.out.println("Client's certificate sent.\n");
                    // Validation server Path
                    CertPath srvCertPath = ValidateCertPath.createPath(serverCertificate);
                    System.out.println("Certificate OK! Validation: " + validateCertPath.validate("./ca.cer", srvCertPath) + "\n");
                    // Getting public Key from certificate
                    PublicKey publicKey = serverCertificate.getPublicKey();
                    
                    // Generating IV and KEY
                    IvParameterSpec IvEnc = Util.IvGen();
                    
                    int bytes_read;
                    int total_bytes = 0;
                    byte[] challenge = new byte[128];
                    getMode.read(challenge);
                    System.out.println("Received chanllenge! sending response!\n");
                    byte[] response = Util.response(clientPrivKey, challenge);
                    sos.write(response);
                    //oos.flush();
                    System.out.println("Response sent!\n");
                    // Changing the way key is generated. KeyStore is used in both sides (Tutorial 4)
                    //SecretKey secretKey = Util.retrieveLongTermKey();
                    // Tutorial 6, using public key received from server to encrypt session key
                    Cipher publicKeyCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    publicKeyCipher.init(Cipher.ENCRYPT_MODE, publicKey);
                    // Tutorial 4.3 using sessionkey and sealedobject
                    SecretKey sessionKey = Util.retrieveSessionKey();
                    SealedObject sealedObject = new SealedObject(sessionKey, publicKeyCipher);
                    System.out.println("Sealed: " + sealedObject.toString());
                    //oos.flush();
                    oos.writeObject(sealedObject);
                    System.out.println("Sent Session Key: " + Util.asHex(sessionKey.getEncoded()));
                    
                    // Sent IV
                    sos.write(IvEnc.getIV());
                    sos.flush();
                    
                    // Create a new cipher with the session key
                    Cipher sessionCipher = Cipher.getInstance(Client.mode);
                    sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey, IvEnc);
                    
                    // Tutorial 4.2 Using CipherOutputStream instead of Cipher
                    CipherOutputStream cos = new CipherOutputStream(sos, sessionCipher);
                    cos.flush();
                    
                    byte[] macTo;
                    int order = -1;
                    
                    //macTo = Util.GenerateMAC(buffer, order, sessionKey, mac);
                    mac = Util.initializeMac(order, sessionKey);
                    
                    while (true) {
                        bytes_read = file.read(buffer);
                        String help = new String(Arrays.copyOfRange(buffer, 0, bytes_read), StandardCharsets.UTF_8);
                        order ++;
                        // Read File 48 bytes each time and print what was read
                            //help = new String(buffer, StandardCharsets.UTF_8);
                            System.out.println("Read from File: " + help + "\n");
                            // Updating Encryption and Write to server
                            macTo = Util.GenerateMAC(Arrays.copyOfRange(buffer, 0, bytes_read), order, sessionKey, mac, bytes_read);
                            //System.out.println("Bytes read "+bytes_read);
                            cos.write(((byte)bytes_read));
                            cos.write(buffer, 0, bytes_read);
                            cos.flush();
                            cos.write(macTo);
                            //System.out.println("Cipher Length: " + buffer.length +
                                    //"\nBytes: " + bytes_read + "\nCipher: " + Arrays.copyOfRange(buffer, 0, bytes_read));
                            // Counting total bytes
                            total_bytes = total_bytes + bytes_read;
                            if(bytes_read < 48) {
                                getMode.close();
                                file.close();
                                cos.close();
                                break;
                            }
                        //}
                    }
                    System.out.println("Read/Wrote this: " + total_bytes + " bytes.\n");
                    System.out.println("Disconnected from server.");
                    
                    // Close socket
                }
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
