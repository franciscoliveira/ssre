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

                    // Upload do certificado do servidor a partir do ValidateCertPath
                    ValidateCertPath validateCertPath = new ValidateCertPath();
                    X509Certificate serverCertificate = ValidateCertPath.getCertFromFile("./server.cer");

                    // Envio do certificado do servidor
                    ObjectOutputStream oos = new ObjectOutputStream(outData);
                    oos.writeObject(serverCertificate);
                    oos.flush();
                    System.out.println("Certificate sent to Client!\n");

                    // Receção do certificado do cliente
                    ObjectInputStream objectIn = new ObjectInputStream(rcv);
                    X509Certificate clientCertificate = (X509Certificate) objectIn.readObject();
                    System.out.println("Certificado do cliente recebido\n");

                    //Caminho para validação do certificado do cliente a partir do ValidateCertPath
                    CertPath clientCertPath = ValidateCertPath.createPath(clientCertificate);

                    // Validação do certificado do cliente
                    Boolean verifies = validateCertPath.validate("./ca.cer", clientCertPath);
                    System.out.println("Certificado do cliente: " + verifies + "\n");

                    //Obtenção da chave pública do cliente a partir do certificado
                    PublicKey clientPublicKey = clientCertificate.getPublicKey();
                    byte[] ch = Util.challenge();
                    oos.write(ch);
                    oos.flush();
                    byte[] response = null;
                    bytes_read = objectIn.read(response);
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
                    ObjectInputStream ois = new ObjectInputStream(rcv);
                    
                    SealedObject sealedObject = (SealedObject)ois.readObject();
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
                    
                    bytes_read = cis.read(message);
                    while(bytes_read != -1){
                        order ++;
                        // Decryption
                        //message = cipher.update(buffer);
                        String ex = new String(message, StandardCharsets.UTF_8);
                        System.out.println("Message: " + ex + "\n");
                        cis.read(macArray);
                        
                        serverMAC = Util.GenerateMAC(Arrays.copyOfRange(message, 0, bytes_read), order, sessionKey, mac);
                        System.out.println("Received MAC: " + Util.asHex(macArray) + 
                                "\nCalculated MAC: " + Util.asHex(serverMAC) + 
                                "\nLengths: " + macArray.length + " read Bytes. | " 
                                + serverMAC.length + " Calculated Bytes.\n");
                        if (Arrays.equals(serverMAC, macArray)){
                            // Read ciphered text
                            if(bytes_read < 48) {
                                //message = cipher.doFinal(buffer);
                                System.out.println("Final Piece! It'll all be over soon!\n");
                                cis.read(macArray);
                                if (Arrays.equals(serverMAC, macArray)){
                                    total_bytes = total_bytes + bytes_read;
                                    finalMove.write(message, 0, bytes_read);
                                    System.out.println("Got Final Piece! Over and OUT! \n Read/Wrote: " + total_bytes + "Bytes.\n" + 
                                            "MAC OK! Over AND OUT!\n");
                                    finalMove.close();
                                    rcv.close();
                                    cis.close();
                                    break;
                                } else {
                                    System.out.println("ERROR! Final piece corrupted!\n");
                                    break;
                                }
                            } else {
                                    System.out.println("MAC OK! Message isn't corrupeted!\nOrder: " + order + "\n");
                                    String ex2 = new String(message, StandardCharsets.UTF_8);
                                    // Write in file what already has decyphered
                                    System.out.println("Bytes: " + bytes_read + 
                                            "\nDecrypted Message Length: " + message.length + 
                                            "\nMessage: " + ex + "\nMAC Length: " + macArray.length + "\n");
                                    finalMove.write(message, 0, bytes_read);
                                    System.out.println("RECEIVED! CIPHER_OK\n");
                                    total_bytes = total_bytes + bytes_read;
                                    bytes_read = cis.read(message);
                            }
                        } else {
                            System.out.println("MAC NOT OK! Message is corrupted or some error occured!\n" +
                                    "RETRY!\n");
                            finalMove.close();
                            break;
                        }
                    }
                } catch (Exception ex) { ex.printStackTrace(); }
                s.close();
                System.out.println("Closed connection.");                
                if(bytes_read == -1)
                    break;
            }           
        } catch (Exception ex) {
            System.err.println(ex.getLocalizedMessage());
            ex.printStackTrace();
        }
    }
}
