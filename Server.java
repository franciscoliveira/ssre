package trunk;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static trunk.Client.mode;

public class Server {
    public static String mode = "";
    //static byte[] key = new byte[16];
    static byte[] iv = new byte[16];
    static public void main(String[] args) {
        try {
            // Create server socket
            ServerSocket ss = new ServerSocket(4567);
            
            // Start upload counter
            int counter = 0;
            
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
                int bytes_read;
                // Get IV and Key from client
                bytes_read = rcv.read(iv);
                
                // bytes_read = rcv.read(key);
                //System.out.println("\nIV: " + Util.asHex(iv) + 
                       // "\nKEY: " + Util.asHex(key) + "\n");
                // Gets cipheredtext to decrypt
                byte[] cipheredText = new byte[48];
                byte[] message;
                int total_bytes = 0;
                try{
                    FileOutputStream finalMove = new FileOutputStream("output");
                    Cipher cipher = Cipher.getInstance(Server.mode);
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    // Changing the way key is generated. KeyStore is used in both sides (Tutorial 4)
                    //SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                    SecretKey secretKey = Util.retrieveLongTermKey();
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
                    bytes_read = rcv.read(cipheredText);
                    while(bytes_read != -1){
                        // Read ciphered text
                        if(bytes_read < 48) {
                            message = cipher.doFinal(cipheredText);
                            total_bytes = total_bytes + bytes_read;
                            finalMove.write(message, 0, bytes_read);
                            System.out.println("Got Final Piece! Over and OUT! \n Read/Wrote: " + total_bytes + "Bytes.\n");
                            finalMove.close();
                            rcv.close();
                            break;
                        }
                        // Decryption
                        message = cipher.update(cipheredText);
                        String ex = new String(message, StandardCharsets.UTF_8);
                        // Write in file what already has decyphered
                        System.out.println("Bytes: " + bytes_read + 
                                "\nDecrypted Message Length: " + message.length + 
                                "\nMessage: " + ex + "\n");
                        finalMove.write(message, 0, bytes_read);
                        System.out.println("RECEIVED! CIPHER_OK\n");
                        total_bytes = total_bytes + bytes_read;
                        bytes_read = rcv.read(cipheredText);
                    }
                } catch (Exception ex) { ex.printStackTrace(); }
                s.close();
                System.out.println("Closed connection.");                
                if(bytes_read == -1)
                    break;
            }           
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
