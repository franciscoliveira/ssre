/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssre_tutorials;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
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
 * @class generateKey
 * @class saveKey
 * @class retrieveKey
 * @class IvGen
 * @class KeyGen
 * @class generateSessionKey
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

    /**
     * Method that Generates and Initializes MAC. This method returns the byte array message after the MAC usage
     * @param message text to cipher using the MAC authentication system
     * @param order sequence number
     * @param key secret Key user for the updates!
     * @return byte array to use
    */
    public static byte[] GenerateMAC(byte[] message, int order, SecretKey key) {
        byte[] returned = null;
        try {
            if(order < 0) {
                // Initialize MAC
                MessageDigest digestM = MessageDigest.getInstance("SHA");
                Client.mac = Mac.getInstance("HmacSHA256"); 
                // First sequence Number
                System.out.println("MAC Initialized!\nOrder: " + order + 
                        "\n");
                order = 0;
                digestM.update((byte)order);
                Client.mac.init(new SecretKeySpec(digestM.digest(), Client.mode));
                return returned;
            } else if(order >= 0) {
                // Updating MAC
                Client.mac.update(key.getEncoded());
                Client.mac.update((byte)order);
                Client.mac.update(message);
                returned = Client.mac.doFinal();
                System.out.println("Generated MAC: "  + Client.mac + "\nUpdating! Order: " + order + 
                        "\nMac: " + Util.asHex(returned) + "\n");
                return returned;
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalStateException e) { e.printStackTrace(); }
        
        return returned;
    }
    
    /**
    *
     * @return 
     * @throws java.security.NoSuchAlgorithmException
    */
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
    
    /**
    *
     * @return 
    */
    public static SecretKey retrieveLongTermKey() {
        SecretKey key = retrieveKey("longterm");
        if(key == null) {
            generateKey("longterm");
            key = retrieveKey("longterm");
        }
        
        return key;
    }
    
    /**
     *
     * @return 
     */
    public static SecretKey retrieveSessionKey()
    {
        return Util.generateSessionKey();
    }
    
    
    /**
    *
     * @return 
    */
    public static IvParameterSpec IvGen (){
            byte[] iv = new byte[16]; //16 bytes = 128 bits
            SecureRandom rand = new SecureRandom();
            rand.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            System.out.println("Initialization Vector: " + asHex(iv));
            return ivSpec;
    }
    
    // Miguel tutorial 4
    
    
    private static void saveKey(SecretKey key, String alias)
    {
        // command line : keytool -list -keystore novaks.jks -storetype JCEKS
        try
        {
            FileInputStream input = null;
            char[] password = null;
            try {
                input = new FileInputStream("novaks.jks");
                password = "password".toCharArray();
            } catch(FileNotFoundException fe) { System.out.println(fe.getMessage()); }
            
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(input, password); 
            
            ks.setKeyEntry(alias, key,"password".toCharArray(),null);
            
            try (FileOutputStream writeStream = new FileOutputStream("novaks.jks")) {
                ks.store(writeStream, "password".toCharArray());
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) { e.printStackTrace(); }
    }
    
    /**
    *
     * @param alias
     * @return 
    */
    public static SecretKey retrieveKey(String alias)
    {
        try{
            FileInputStream input = new FileInputStream("novaks.jks");
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(input,"password".toCharArray());
            SecretKey sk = (SecretKey) ks.getKey(alias, "password".toCharArray());
            return sk;
        } catch (Exception e){ System.err.println(e.getMessage()); }
        return null;
    }
    
    /**
    *
     * @param alias
    */
    public static void generateKey(String alias)
    {
            try{
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                SecretKey sk = kg.generateKey();
                saveKey(sk, alias);
            } catch (Exception e) { System.err.println(e.getMessage()); }  
    } 
    
    /**
    *
     * @return 
    */
    public static SecretKey generateSessionKey()
    {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            SecretKey sk = kg.generateKey();
            return sk;
        } catch (Exception e) { System.err.println(e.getMessage()); }
        return null;
    }
}
