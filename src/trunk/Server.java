package trunk;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Server {
    public static String mode = "";
    public static Mac mac = null;
    //static byte[] key = new byte[16];
    static byte[] iv = new byte[16];
    static public void main(String[] args) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException {
        try {
            // Create server socket
            ServerSocket ss = new ServerSocket(4567);
            
            // Start upload counter
            int counter = 0;
            int bytes_read = -1;
            
            System.out.println("Server started ...");

            while(true) {
                // Wait for client            
                Socket s = ss.accept();
                // Increment counter
                counter++;
                System.out.println("Accepted connection " + counter + ".");
                // Get file 50 bytes at a time
                byte[] buffer = new byte[50];
                //accepted the connection now choose mode
                Util.ModeChoosing();
                //send mode to the client
                // Get socket input stream
                InputStream rcv = s.getInputStream();
                OutputStream outData = s.getOutputStream();
                outData.write(mode.getBytes("UTF-8"));
                
                
                byte[] message = new byte[48];
                int total_bytes = 0;
                try{
                    // Tutorial 6, sending public key to client
                    // KeyPair keyPair = Util.generateSessionRSAPair();
                    // Tutorial 7, getting public keyPair from a file and signature
                    /*KeyPair keyPair = Util.retrieveRSAPair("server");
                    byte[] signature = Util.retrieveSignature();
                    System.out.println("Signature: " + Util.asHex(signature));
                    //if(Util.verifySignature(signature, keyPair.getPublic()))
                        System.out.println("Signature is correct");
                    
                    PublicKey publicKey = keyPair.getPublic();
                    PrivateKey privateKey = keyPair.getPrivate();
                    ObjectOutputStream oos = new ObjectOutputStream(outData);
                    oos.writeObject(publicKey);
                    System.out.println("Sent public key: " + Util.asHex(publicKey.getEncoded()));
                    oos.writeObject(signature);*/
                    // Tutorial 8 obtaining keys/certificates/validations
                    RSAPrivateKey privateKey = Util.getPrivateKeys("server");
                    // Get certificate
                    ValidateCertPath validateCertPath = new ValidateCertPath();
                    X509Certificate serverCertificate = ValidateCertPath.getCertFromFile("./server.cer");
                    // Send certificate
                    ObjectOutputStream oos = new ObjectOutputStream(outData);
                    oos.writeObject(serverCertificate);
                    //oos.flush();
                    System.out.println("Certificate sent to Client!\n");
                    // Receives Client's certificate
                    ObjectInputStream objectIn = new ObjectInputStream(rcv);
                    X509Certificate clientCertificate = (X509Certificate) objectIn.readObject();
                    System.out.println("Got Client's certificate!\n");
                    // Check validation Path
                    CertPath clientCertPath = ValidateCertPath.createPath(clientCertificate);
                    Boolean verifies = validateCertPath.validate("./ca.cer", clientCertPath);
                    if (verifies = true) System.out.println("Client's OK! Verification: " + verifies + "\n");
                    else {
                        System.err.println("Certificate not valid! ERROR! BREAK!\n");
                        break;
                    }
                    // Getting public key from certificate
                    PublicKey clientPublicKey = clientCertificate.getPublicKey();
                    byte[] ch = Util.challenge();
                    outData.write(ch);
                    //oos.flush();
                    byte[] response = new byte[256];
                    bytes_read = rcv.read(response);
                    boolean ok = Util.verifyResponse(clientPublicKey, ch, response);
                    if(ok == true) System.out.println("Everything is ok in Challenge-Response!\n");
                    else System.out.println("ERROR in Challenge Response!\n");
                    
                    FileOutputStream finalMove = new FileOutputStream("output.txt");
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    
                    // Changing the way key is generated. KeyStore is used in both sides (Tutorial 4)
                    //SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                    //SecretKey secretKey = Util.retrieveLongTermKey();
                    // Tutorial 6, changing symmetric cipher for RSA pair
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                    //bytes_read = rcv.read(buffer);
                    
                    // Tutorial 4.3 using sessionkey and sealedObject
                    //ObjectInputStream ois = new ObjectInputStream(rcv);
                    
                    SealedObject sealedObject = (SealedObject)objectIn.readObject();
                    SecretKey sessionKey = (SecretKey)sealedObject.getObject(cipher);
                    System.out.println("Received Session Key: " + Util.asHex(sessionKey.getEncoded()) + "\n");
                    
                    // Get IV and Key from client
                    bytes_read = rcv.read(iv);
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    System.out.println("\nIV: " + Util.asHex(iv) + "\n");

                    // Create new cipher with the session key
                    Cipher sessionCipher = Cipher.getInstance(Server.mode);
                    sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
                    
                    // Tutorial 4.2 Using CipherInputStream instead of Cipher
                    CipherInputStream cis = new CipherInputStream(rcv, sessionCipher);
                    
                    // MAC initializing
                    int order = -1;
                    //Util.GenerateMAC(buffer, order, sessionKey, mac);
                    mac = Util.initializeMac(order, sessionKey);
                    byte[] macArray = new byte[32];
                    byte[] serverMAC;
                    int mac_bytes = 0;
                    while(true){
                        order ++;
                        cis.read(message,0,1);
                        bytes_read = message[0] & 0xFF;
                        bytes_read = cis.read(message,0,bytes_read);
                        System.out.println("Bytes read :"+bytes_read);
                        
                        String ex = new String(Arrays.copyOfRange(message, 0, bytes_read), StandardCharsets.UTF_8);
                        // Decryption
                        //message = cipher.update(buffer);                        
                       
                        mac_bytes = cis.read(macArray);
                        System.out.println("Read Mac: "+Util.asHex(macArray));
                        // Final Piece
                        if(bytes_read < 48) {
                            System.out.println("Last Message Received: "+ex);
                            //message = cipher.doFinal(buffer);
                            System.out.println("It'll all be over soon!\n Final Piece: " + ex + "\n");
                            serverMAC = Util.GenerateMAC(Arrays.copyOfRange(message, 0, bytes_read), order, sessionKey, mac, bytes_read);
                            System.out.println("I'm here!\n");   
                            if (Arrays.equals(serverMAC, macArray)){
                                // Does final read, prints number of total bytes read
                                // Tells the Client that everything is done!
                                total_bytes = total_bytes + bytes_read;
                                finalMove.write(message, 0, bytes_read);
                                System.out.println("Got Final Piece! Over and OUT! \n Read/Wrote: " + total_bytes + "Bytes.\n" + 
                                        "MAC OK! Over AND OUT!\n");
                                outData.write("It's Done finally!\n".getBytes("UTF-8"));
                                outData.close();
                                finalMove.close();
                                rcv.close();
                                cis.close();
                                break;
                            } else {
                                System.err.println("ERROR! Final piece corrupted!\n" + 
                                       "Received MAC: " + Util.asHex(macArray) + 
                                       "\nCalculated MAC: " + Util.asHex(serverMAC) + 
                                       "\nLengths: " + macArray.length + " read Bytes. | " 
                                       + serverMAC.length + " Calculated Bytes.\n" );
                                break;
                            }
                        } else {
                            //mac_bytes = cis.read(macArray);
                            System.out.println("Message: " + ex + "\n");
                            serverMAC = Util.GenerateMAC(Arrays.copyOfRange(message, 0, bytes_read), order, sessionKey, mac, bytes_read);
                            System.out.println("Received MAC: " + Util.asHex(macArray) + 
                                "\nCalculated MAC: " + Util.asHex(serverMAC) + 
                                "\nLengths: " + macArray.length + " read Bytes. | " 
                                + serverMAC.length + " Calculated Bytes.\n");
                            
                            if(Arrays.equals(serverMAC, macArray)) {
                                System.out.println("MAC OK! Message isn't corrupeted!\nOrder: " + order + "\n");
                                // Write in file what already has been decyphered
                                System.out.println("Bytes: " + bytes_read + 
                                       "\nDecrypted Message Length: " + message.length + 
                                       "\nMessage: " + ex + "\nMAC Length: " + macArray.length + "\n");
                                finalMove.write(message, 0, bytes_read);
                                System.out.println("RECEIVED! Message OK!\n");
                                total_bytes = total_bytes + bytes_read;
                                //bytes_read = cis.read(message);
                            } else {
                                System.err.println("ERROR! Message Corrupted! Mac isn't working!\n");
                                break;
                            }
                        }    
                    }
                } catch (Exception ex) { System.err.println(ex.getLocalizedMessage()); }
                s.close();
                System.out.println("Closed connection.");                
                if(bytes_read == -1)
                    break;
            }           
        } catch (Exception ex) {
            System.err.println(ex.getLocalizedMessage()); }
    }
}
