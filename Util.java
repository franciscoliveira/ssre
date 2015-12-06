/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package trunk;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Methods that can be used for the server and Client classes
 * @class ModeChoosing creates on the console a "Menu" for the user to choose the AES encryption mode
 * or the RC4 Encryption
 * @class asHex has a byte array input and returns a String with the Hexadecimal conversion of the bytes
 * its main purpose it's to make the bytes kind of readable for the programmer
 * @class GenerateMAC as the data byte array and the secret key as an input and returns the MAC byte array of the
 * junction between the message and the MAC
 * @author chico
 */
public class Util {
    public static void ModeChoosing(){
        while(true){
            Scanner userIn = new Scanner(System.in);
            System.out.println("Encryption Modes:\n" + 
                    "• 1 - RC4\n" +
                    "• 2 - AES/CBC/NoPadding\n" +
                    "• 3 - AES/CBC/PKCS5Padding\n" +
                    "• 4 - AES/CFB8/PKCS5Padding\n" +
                    "• 5 - AES/CFB8/NoPadding\n" +
                    "• 6 - AES/CFB/NoPadding\n" +
                    "Select an Option and Press Enter: ");
            int mode = userIn.nextInt();
            switch(mode){
                default: Server.mode = "ERROR";
                case 1: Server.mode = "RC4";
                case 2: Server.mode = "AES/CBC/NoPadding";
                case 3: Server.mode = "AES/CBC/PKCS5Padding";
                case 4: Server.mode = "AES/CFB8/PKCS5Padding";
                case 5: Server.mode = "AES/CFB8/NoPadding";
                case 6: Server.mode = "AES/CFB/NoPadding";
            }
            if(Server.mode.contentEquals("ERROR")) System.out.println("Invalid option. Choose again!\n");
            else System.out.println("Selected mode: " + Server.mode);
            break;
        }
    }
    
    /**
     * Turns array of bytes into Hexadecimal string
     *
     * @param buf   Array of bytes to convert to hex string
     * @return  Generated hex string
    */
    public static String asHex(byte buf[]) {
        StringBuilder strbuf = new StringBuilder(buf.length * 2);
        int i;
        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10) {
                strbuf.append("0");
            }
            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }
        return strbuf.toString();
    }
    
    /*
    * Method that Generates and Initializes MAC. This method returns the byte array message after the MAC usage
    * @param byte[] message
    * @SecretKeySpec key
    * @return byte[] 
    */
    public static byte[] GenerateMAC(byte[] message, SecretKeySpec key) {
        byte[] digest = null;
        try {
            // create a MAC and initialize with the above key
            Mac mac = Mac.getInstance(key.getAlgorithm());
            mac.init(key);
            // create a digest from the byte array
            digest = mac.doFinal(message);
            
            //isabel
            //MessageDigest dgst = MessageDigest.getInstance("SHA");
       //dgst.update((byte)evo);
       //Mac mac2 = Mac.getInstance("HmacSHA256");  
       //mac.init(new SecretKeySpec(dgst.digest(), mode)); 
       System.out.println("mac iniciado");

        } catch (Exception e) { e.printStackTrace(); }
        
        return digest;
    }
    
    public static SecretKeySpec KeyGen() throws NoSuchAlgorithmException{
            // key generation randomly 128
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            //SecretKey key = keyGen.generateKey();
            byte[] key = keyGen.generateKey().getEncoded();
            SecretKeySpec sKeySpec = new SecretKeySpec(key, "AES");
            System.out.println("Key: " + asHex(sKeySpec.getEncoded()) + "\n");
            //storingkey
            FileOutputStream fileKey;
        try {
            fileKey = new FileOutputStream("key.txt");
            fileKey.write(key);
            fileKey.close();
        } catch (IOException ex) { Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex); }
            return sKeySpec;
    }
    
    public static SecretKey retrieveLongTermKey() 
    {
        SecretKey key = GenerateKey.retrieveKey("longterm");
        if(key == null)
        {
            GenerateKey.generateKey("longterm");
            key = GenerateKey.retrieveKey("longterm");
        }
        
        return key;
    }
    
    public static byte[] Encryption(byte[] info, IvParameterSpec ivSpec, SecretKeySpec sKeySpec, int order){
        byte[] cph = new byte[50];
        try {
            //initialization vector
            // random seed for the initialization vector 128
            Cipher cipher = Cipher.getInstance(Client.mode);
            cipher.init(Cipher.ENCRYPT_MODE, sKeySpec, ivSpec);
            // read data from buffer
            // encrypt
            if(order > 0 && order == 50) cph = cipher.update(info);
            else cph = cipher.doFinal(info);
            // write cph to file bjgjkhj
            FileOutputStream fos = new FileOutputStream("encripted.txt");
            fos.write(cph);   
            fos.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return cph;
    }
     
    public static IvParameterSpec IvGen (){
            byte[] iv = new byte[16]; //16 bytes = 128 bits
            SecureRandom rand = new SecureRandom();
            rand.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            System.out.println("Initialization Vector: " + asHex(iv));
            return ivSpec;
    }
}
