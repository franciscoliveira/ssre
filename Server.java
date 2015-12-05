package ssre_tutorials;

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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static ssre_tutorials.Client.mode;

public class Server {
    public static String mode = "";
    static byte[] key = new byte[16];
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
                byte[] buffer = new byte[16];
                //accepted the connection now choose mode
                Util.ModeChoosing();
                //send mode to the client
                // Get socket input stream
                InputStream rcv = s.getInputStream();
                OutputStream outData = s.getOutputStream();
                outData.write(mode.getBytes("UTF-8"));
                while(true) {
                    rcv.read(buffer);
                    String helper = new String(buffer, StandardCharsets.UTF_8);
                    System.out.println("HELPER: " + helper + "\n" + helper.compareTo(mode));
                    if(helper.compareTo(mode) == 0 || helper.compareTo(mode) > 0 /*|| buffer == ("MODE_OK".getBytes("UTF-8"))*/) {
                        System.out.println("ACK Received! MODE_OK\n");
                        break;
                    } else {
                        System.out.println("NO ACK! MODE_NOT_OK\n HELPER: " + helper + "\n");
                        outData.write(mode.getBytes("UTF-8"));
                    }
                }
                // Open file to write to
                //FileOutputStream fos = new FileOutputStream("Decyphered" + "_" + (counter-1));
                int bytes_read = 0;
                int i = 0;
                //byte[] iv = null;
                //byte[] key = null;
                String fileName = "";
                OutputStream state = s.getOutputStream();
                while(true){
                    if(bytes_read != 0) bytes_read = rcv.read(buffer, 0, 16);
                    else bytes_read = rcv.read(buffer);
                    String helper = new String(buffer, StandardCharsets.UTF_8);
                    System.out.println("HELPER: " + helper + "\nCount: " + i +
                            "\nBytes: " + bytes_read + "\n");
                    if(bytes_read > 0 && i == 1 && !mode.equals("RC4")) {
                        // IV read
                        //byte[] iv = new byte[bytes_read];
                        iv = buffer;
                        System.out.println("IV OK! Buffer: " + Util.asHex(buffer)+ "\n" + 
                                "IV: " + Util.asHex(iv) + "\n" + "Count: " + i + "\n" + 
                                "Bytes: " + bytes_read + "\n");
                        state.write("IV_OK".getBytes("UTF-8"));
                        state.flush();
                        i++;
                    } else if(bytes_read <= 0 && i == 1 && !mode.equals("RC4")){
                        // If there isn't any IV let the Client know
                        System.out.println("ERROR! IV not received");
                        state.write("IV_NOT_OK".getBytes("UTF-8"));
                        state.flush();
                    } else if(bytes_read > 0 && i == 2 && !mode.equals("RC4")){
                        // KEY read
                        //byte[] key = new byte[16];
                        key = buffer;
                        System.out.println("KEY OK! Buffer: " + Util.asHex(buffer) 
                                + "\nKey: " + Util.asHex(key) + "\nCount: " + i + "\n");
                        state.write("KEY_OK".getBytes("UTF-8"));
                        state.flush();
                        break;
                    } else if(bytes_read <= 0 && i == 2) {
                        // If there isn't any KEY let the Client know
                        System.out.println("ERROR! KEY not received");
                        state.write("KEY_NOT_OK".getBytes("UTF-8"));
                        state.flush();
                    } else if(bytes_read > 0 && i == 0){
                        fileName = helper;
                        System.out.println("FILENAME OK! HELPER: " + helper +
                                "\nFILENAME: " + fileName + "\nCount: " + i + "\n");
                        state.write("FILENAME_OK".getBytes("UTF-8"));
                        state.flush();
                        i++;
                    } else {//if(bytes_read > 0 && i == 1){
                        // If there isn't any KEY let the Client know
                        System.out.println("ERROR! FILENAME: " + fileName + 
                                "\nHELPER: " + helper + " \n");
                        state.write("FILENAME_NOT_OK".getBytes("UTF-8"));
                        state.flush();
                    }
                }
                    String[] typeFile = fileName.split(Pattern.quote("."));
                    //fileName = fileName + ".lel";
                    //typeFile = fileName.split(".");
                    String finalName = "output." + typeFile[1];
                    // Gets cipheredtext to decrypt
                    byte[] cipheredText = new byte[50];
                    //bytes_read = rcv.read(cipheredText);
                    boolean howareyou = true;
                    byte[] message;
                    try{
                        //System.out.println("Printing to: " + finalName + "\n");
                        FileOutputStream finalMove = new FileOutputStream("output.txt");
                        //output.createNewFile();
                        //if(!output.canWrite()) 
                          //  System.out.println("CANT WRITE! \n");
                        Cipher cipher = Cipher.getInstance(Server.mode);
                        IvParameterSpec ivSpec = new IvParameterSpec(iv);
                        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
                        
                        while(bytes_read != -1){
                            //howareyou = false;
                            bytes_read = rcv.read(cipheredText);
                            String alfa = new String(cipheredText, StandardCharsets.UTF_8);
                            //if(bytes_read > 0 ){
                                // Decryptiongjfjgjkhiu
                                //message = Util.Decryption(cipheredText, iv, key, bytes_read);
                                message = cipher.update(cipheredText);
                                String ex = new String(message, StandardCharsets.UTF_8);
                                // Write in file what already has decyphered
                                System.out.println("Length: " + message.length + "\n" + 
                                        "Bytes: " + bytes_read + "\n" 
                                        + "Message: " + ex + "\n" + "Ciphered: " + alfa);
                                finalMove.write(message, 0, message.length);
                                //finalMove.flush();
                                //bytes_read = rcv.read(cipheredText);
                                System.out.println("RECEIVED! CIPHER_OK\n");
                                /*state.write("CIPHER_OK".getBytes("UTF-8"));
                                state.flush();*/
                                if(bytes_read < 50) {
                                    cipher.doFinal();
                                    System.out.println("Got Final Piece! Over and OUT! \n");
                                    finalMove.close();
                                    break;
                              //  }
                            //} else {
                              //  System.out.println("Something went wrong! CIPHER_NOT_OK!\n");
                                //state.write("CIPHER_NOT_OK".getBytes("UTF-8"));
                                //state.flush();
                            }
                        }
                    } catch (Exception ex) { ex.printStackTrace(); }
                /*while (bytes_read > 0) {
                   if(i == 0){
                   decrypted = Util.Decryption(buffer, iv, i);
                   fos.write(buffer, 0, bytes_read);
                   bytes_read = rcv.read(buffer);
                   System.out.println("Read: " + Util.asHex(buffer));
                   System.out.println("Deciphered: " + Util.asHex(decrypted));
                   i++;
                   }
                   else {
                   if(bytes_read == -1)
                       i=-1;
                   else 
                       i++;
                   decrypted = Util.Decryption(buffer, iv, i);
                   fos.write(buffer, 0, bytes_read);
                   bytes_read = rcv.read(buffer);
                   System.out.println("Read (" + bytes_read + "bytes) : " + Util.asHex(buffer));
                   System.out.println("Deciphered (" + decrypted.length + ") :" + Util.asHex(decrypted));
                   }*/

                // Close socket
                s.close();
                System.out.println("Closed connection.");                
                // Close file
                //fos.close();
                if(bytes_read == -1)
                    break;
                /*System.out.println("Close server (Y/N)? ");
                Scanner finish = new Scanner(System.in);
                String var = new String();
                if(var.equals("Y") || var.equals("y")) s.close();*/
            }           
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
