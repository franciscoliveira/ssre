/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssre_tutorials;

/**
 *
 * @author chico
 */

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.Mac;
import javax.crypto.SealedObject;

public class Client {
    public static String mode = "";
    public static Mac mac = null;
    static public void main(String[] arg) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        byte[] ciphered = new byte[100];
        try {
            
            // Connect to server
            Socket s = new Socket("127.0.0.1",4567);
            byte[] buffer = new byte[48];
            System.out.println("Connected to server...");
            System.out.println("File Name?\n");
            Scanner in = new Scanner(System.in);
            String filename = in.nextLine();
            // Open file to upload
            FileInputStream file = new FileInputStream(filename);
            BufferedInputStream BufIn = new BufferedInputStream (file);
            // Get socket output stream
            OutputStream sos = s.getOutputStream();
            // Gets the mode from the server
            InputStream getMode = s.getInputStream();
            getMode.read(buffer);
            String ex = new String(buffer, StandardCharsets.UTF_8);
            mode = ex;
            System.out.println("MODE: " + mode + "\n");
            // Generating IV and KEY
            int bytes_read = 0;
            int total_bytes = 0;
            IvParameterSpec IvEnc = Util.IvGen();
            
            // Changing the way key is generated. KeyStore is used in both sides (Tutorial 4)
            //SecretKeySpec KeyEnc = Util.KeyGen();
            SecretKey secretKey = Util.retrieveLongTermKey();
            //SecretKey secretKeyNumb2 = Util.retrieveLongTermKey();
            
            sos.write(IvEnc.getIV());
            sos.flush();
            
            // Changing the way key is generated. KeyStore is used in both sides (Tutorial 4)
            //sos.write(secretKey.getEncoded());
            //sos.flush();
            
            Cipher longTermCipher = Cipher.getInstance(Client.mode);
            longTermCipher.init(Cipher.ENCRYPT_MODE, secretKey, IvEnc);
            // Tutorial 4.3 using sessionkey and sealedobject
            SecretKey sessionKey = Util.retrieveSessionKey();
            SealedObject sealedObject = new SealedObject(sessionKey, longTermCipher);
            ObjectOutputStream oos = new ObjectOutputStream(sos);
            oos.writeObject(sealedObject);
            // Create a new cipher with the session key
            Cipher sessionCipher = Cipher.getInstance(Client.mode);
            sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey, IvEnc);
            
            // Tutorial 4.2 Using CipherOutputStream instead of Cipher 
            CipherOutputStream cos = new CipherOutputStream(sos, sessionCipher);
            /*while((bytes_read = file.read(buffer)) != -1)
            {
                cos.write(buffer, 0, bytes_read);
                total_bytes += bytes_read;
            }
            cos.close();*/
            //bytes_read = BufIn.read(buffer);
            
            
            bytes_read = file.read(buffer);
            byte[] macTo;
            int order = -1;
            
            macTo = Util.GenerateMAC(buffer, order, secretKey);
            
            while (true) {
                order ++;
                /*if(macTo == null) {
                    System.err.println("ERROR! Mac Initialization!");
                    break;
                }*/
                // Read File 48 bytes each time and print what was read
                if(bytes_read < 48) {
                    System.out.println("Over and Out!\n");
                    
                    //ciphered = sessionCipher.doFinal(buffer);
                    macTo = Util.GenerateMAC(buffer, order, secretKey);
                    cos.write(buffer, 0, bytes_read);
                    cos.flush();
                    cos.write(macTo, 0, macTo.length);
                    cos.close();
                    total_bytes = total_bytes + bytes_read;
                    break;
                }
                String help = new String(buffer, StandardCharsets.UTF_8);
                System.out.println("Read from File: " + help + "\n");
                // Updating Encryption and Write to server
                //ciphered = cipher.update(buffer);
                macTo = Util.GenerateMAC(buffer, order, secretKey);
                cos.write(buffer, 0, bytes_read);
                cos.flush();
                cos.write(macTo);
                System.out.println("Cipher Length: " + ciphered.length + 
                        "\nBytes: " + bytes_read + "\n");
                //bytes_read = BufIn.read(buffer);
                bytes_read = file.read(buffer);
                // Counting total bytes
                total_bytes = total_bytes + bytes_read;
            }
            System.out.println("Read/Wrote this: " + total_bytes + " bytes.\n");
            System.out.println("Disconnected from server.");

            // Close socket
            sos.close();
            cos.close();
            // Close file
            BufIn.close();
            file.close();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
