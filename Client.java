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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;

public class Client {
    public static String mode = "";
    static public void main(String[] arg) {
        byte[] ciphered = new byte[100];
        try {
            
            // Connect to server
            Socket s = new Socket("127.0.0.1",4567);
            byte[] buffer = new byte[50];
            System.out.println("Connected to server...");
            System.out.println("File Name?\n");
            Scanner in = new Scanner(System.in);
            String filename = in.nextLine();
            // Open file to upload
            FileInputStream fis = new FileInputStream(filename);
            // Get socket output stream
            OutputStream sos = s.getOutputStream();
            // Gets the mode from the server
            InputStream getMode = s.getInputStream();
            while(true) {
                getMode.read(buffer);
                String helper = new String(buffer, StandardCharsets.UTF_8);
                mode = helper;
                //System.out.println("MODE: " + mode + "\n" + "HELPER: " + helper + "\n");
                if(helper.equals("")) {
                    System.out.println("Didn't received mode properly!\n");
                    sos.write("MODE_NOT_OK".getBytes("UTF-8"));
                } else {
                    System.out.println("Received! MODE : " + mode + "\n");
                    sos.write("MODE_OK".getBytes("UTF-8"));
                    break;
                }
            }
            InputStream getACK = s.getInputStream();
            while(true){
                // Sends the filename so the server can replicate it
                sos.flush();
                sos.write(filename.getBytes("UTF-8"));
                getACK.read(buffer);
                String helper = new String(buffer, StandardCharsets.UTF_8);
                if(helper.compareTo("FILENAME_OK") >= 0) {
                    System.out.println("ACK Received! FILENAME_OK");
                    break;
                } else {
                    System.out.println("ERROR! FILENAME_NOT_OK");
                    sos.write(filename.getBytes("UTF-8"));
                }
            }
            // reads the file to know the number of bytes it has
            int bytes_read = 0;
            int total_bytes = 0;
            IvParameterSpec IvEnc = Util.IvGen();
            SecretKeySpec KeyEnc = Util.KeyGen();
            while(true){
                sos.flush();
                sos.write(IvEnc.getIV());
                getACK.read(buffer);
                String helper = new String(buffer, StandardCharsets.UTF_8);
                if(helper.compareTo("IV_OK") >= 0) {
                    System.out.println("ACK Received! IV_OK\n");
                        sos.flush();
                        sos.write(KeyEnc.getEncoded());
                        getACK.read(buffer);
                        String confirm = new String(buffer, StandardCharsets.UTF_8);
                        if(confirm.compareTo("KEY_OK") >= 0) {
                            System.out.println("ACK Received! KEY_OK\n");
                            break;
                        } else { System.out.println("ERROR! KEY_NOT_OK\n"); }
                } else System.out.println("ERROR! IV_NOT_OK\n");
            }
            //byte[] ack = new byte[13];
            //ack = "CIPHER_OK".getBytes();
            //boolean howareyou = false;
            //int compare = 0;
            //String helper = new String(ack, StandardCharsets.UTF_8);
            //if it read all the bytes: stop
            Cipher cipher = Cipher.getInstance(Client.mode);
            cipher.init(Cipher.ENCRYPT_MODE, KeyEnc, IvEnc);
            System.out.println("Reading...\n");
            OutputStream outCipher = s.getOutputStream();
            outCipher.flush();
            while (true) {
                //String helper = new String(ack, StandardCharsets.UTF_8);
                bytes_read = fis.read(buffer);
                //if(total_bytes < bytes_read) {njhkjkhj
                    System.out.println("First Round! Sent!\n");
                    //ciphered = Util.Encryption(buffer, IvEnc, KeyEnc, bytes_read);
                    ciphered = cipher.update(buffer);
                    outCipher.write(ciphered, 0, ciphered.length);
                    outCipher.flush();
                    total_bytes = total_bytes + bytes_read;
                    String helper = new String(buffer, StandardCharsets.UTF_8);
                    System.out.println("HELPER: " + helper + "\n");
                    if(bytes_read < 50) 
                        break;
                    /*
                    if(helper.compareTo("CIPHER_OK") >= 0) {
                        System.out.println("First Round Reception: OK! \n");
                        howareyou = true;
                    } else{
                        sos.write(ciphered, 0, ciphered.length);
                        System.out.println("ERROR! CIPHER_NOT_OK!\n");
                        break;
                    }*/
                /*} else /*if(compare >= 0 || howareyou){
                    System.out.println("Server state: RECEIVING...");
                    //ciphered = Util.Encryption(buffer, IvEnc, KeyEnc, bytes_read);
                    ciphered = cipher.update(buffer);
                    outCipher.write(ciphered, 0, ciphered.length);
                    outCipher.flush();
                    total_bytes = total_bytes + bytes_read;
                    //getACK.read(ack);
                } /*else {
                    sos.write(ciphered, 0, ciphered.length);
                    System.out.println("ERROR! CIPHER_NOT_OK!\n");
                }
                String helper = new String(ack, StandardCharsets.UTF_8);
                compare = helper.compareTo("CIPHER_OK");*/
            }
            cipher.doFinal();
            System.out.println("Read/Wrote this: " + total_bytes + " bytes.\n");
            //sos.write(ciphered, 0, ciphered.length);
            //sos.flush();

            System.out.println("Disconnected from server.");

            // Close socket
            sos.close();
            // Close file
            fis.close();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
