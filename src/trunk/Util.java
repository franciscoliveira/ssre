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
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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

    public static Mac initializeMac(int order, SecretKey key)
    {
        try
        {
            // Initialize MAC
            MessageDigest digestM = MessageDigest.getInstance("SHA");
            Mac mac = Mac.getInstance("HmacSHA256"); 
            // First sequence Number
            System.out.println("MAC Initialized!\nOrder: " + order + 
                        "\n");
            order = 0;
            digestM.update((byte)order);
            mac.init(new SecretKeySpec(digestM.digest(), Client.mode));
            return mac;
        } catch (Exception e)
        {
            System.err.println(e.getLocalizedMessage());
        }
        return null;
    }
    
    /**
     * Method that Generates and Initializes MAC. This method returns the byte array message after the MAC usage
     * @param message text to cipher using the MAC authentication system
     * @param order sequence number
     * @param key secret Key user for the updates!
     * @param mac
     * @return byte array to use
    */
    public static byte[] GenerateMAC(byte[] message, int order, SecretKey key, Mac mac) {
        byte[] returned = null;
        try {
            if(order < 0) {
                // Initialize MAC
                MessageDigest digestM = MessageDigest.getInstance("SHA");
                mac = Mac.getInstance("HmacSHA256"); 
                // First sequence Number
                System.out.println("MAC Initialized!\nOrder: " + order + 
                        "\n");
                order = 0;
                digestM.update((byte)order);
                mac.init(new SecretKeySpec(digestM.digest(), Client.mode));
                return returned;
            } else if(order >= 0) {
                // Updating MAC
                mac.update(key.getEncoded());
                mac.update((byte)order);
                mac.update(message);
                returned = mac.doFinal();
                System.out.println("Generated MAC: "  + mac + "\nUpdating! Order: " + order + 
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
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                UnrecoverableKeyException e){ System.err.println(e.getMessage()); }
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
    
    /**
     * 
     */
    private static KeyPair generateSessionRSAPair()
    {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            return kp;
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
        }
        return null;
    }
    
    /**
     *
     * @param belongs String expecting "server" or "TA" 
     * @return KeyPair of belongs specified
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IOException
     */
    public static KeyPair retrieveRSAPair(String belongs) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
    {
        String publicKeyFile;
        String privateKeyFile;
        
        if(((belongs.compareTo("server") == 0) || (belongs.compareTo("TA") ==0)) != true)
        {
            System.err.println("Bad usage: string must be server or TA");
            return null;
        } else
        {
            publicKeyFile = belongs + "publicKey";
            privateKeyFile = belongs + "privateKey";
        }
        
        FileInputStream pkis = null;
        FileInputStream privatekis = null;
        FileOutputStream pkos = null;
        FileOutputStream privatekos = null;
        PublicKey publicKey;
        PrivateKey privateKey;
        
        boolean pairExists = true;
        try {
            pkis = new FileInputStream(publicKeyFile);
            privatekis = new FileInputStream(privateKeyFile);
        } catch (FileNotFoundException e)
        {
            pairExists = false;
        }
        
        KeyPair kp;
        byte[] publicKeyBytes = new byte[2048];
        byte[] privateKeyBytes = new byte[2048];
        
        if(pairExists)
        {
            try {
                pkis.read(publicKeyBytes);
                privatekis.read(privateKeyBytes);
            } catch (IOException ex) {
                Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publickSpec = new X509EncodedKeySpec(publicKeyBytes);
            publicKey = keyFactory.generatePublic(publickSpec);
            
            EncodedKeySpec privatekSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            privateKey = keyFactory.generatePrivate(privatekSpec);
            
            kp = new KeyPair(publicKey, privateKey);
            
        } else 
        {
            
            kp = generateSessionRSAPair();
            publicKey = kp.getPublic();
            privateKey = kp.getPrivate();
            
            try {    
                pkos = new FileOutputStream(publicKeyFile);
                privatekos = new FileOutputStream(privateKeyFile);
                pkos.write(publicKey.getEncoded());
                privatekos.write(privateKey.getEncoded());
            } catch (IOException ex) {
                Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        return kp;
    }
    
    /**
     * 
     */
    private static byte[] signRSAPair(KeyPair kp) throws NoSuchAlgorithmException, 
            InvalidKeyException, InvalidKeySpecException, IOException, SignatureException
    {
        byte[] sign;
        
        KeyPair TAKeyPair = retrieveRSAPair("TA");
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(TAKeyPair.getPrivate());
        signature.update(kp.getPublic().getEncoded());
        sign = signature.sign();
        
        return sign;
    }
    
    /**
     * Retrieve signature for the server public key; if it doesn't exists, it creates one.
     * 
     * @return Return Signature
     */
    public static byte[] retrieveSignature() 
    {
        boolean exists = true;
        byte[] signature = new byte[256];
        FileInputStream fis = null;
        FileOutputStream fos;
        try {
            fis = new FileInputStream("sign");
        } catch (FileNotFoundException ex) {
            exists = false;
        }
        
        if(exists)
        {
            try {
                fis.read(signature);
                fis.close();
            } catch (Exception e) {
                System.err.println(e.getLocalizedMessage());
            }
            return signature;
        } else
        {
            try {
                signature = signRSAPair(retrieveRSAPair("server"));
                fos = new FileOutputStream("sign");
                fos.write(signature);
                fos.close();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException | 
                    InvalidKeyException | SignatureException e) { System.err.println(e.getLocalizedMessage()); }
            return signature;
        }
    }
    
    /**
     * Verify signature for a chosen public key using TA Public Key in the file system
     * @param signature signature that is going to be verified
     * @param publicKey public key that is going to be verified
     * @return Returns true or false either the signature is valid
     */
    public static boolean verifySignature(byte[] signature, PublicKey publicKey)
    {
        try
        {
            KeyPair TAKeyPair = retrieveRSAPair("TA");
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(TAKeyPair.getPublic());
            sig.update(publicKey.getEncoded());
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException | InvalidKeyException 
                | SignatureException e) { System.err.println("Verify Signature: " + e.getLocalizedMessage()); }
        return false;
    }
    
    /** Function that returns the stored private Key either or Client or server
     * 
     * @param side Variable which defines if the key is for the server or the Client
     * @return PrivateKey for either server either client
     * @throws java.io.FileNotFoundException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws java.security.NoSuchAlgorithmException
     */
    static public RSAPrivateKey getPrivateKeys(String side) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        
        byte[] encodedKey;
        try (FileInputStream PK8Key = new FileInputStream(side + ".pk8")) {
            encodedKey = new byte[PK8Key.available()];
            PK8Key.read(encodedKey);
        }
        PKCS8EncodedKeySpec PK8KeySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyGen = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) keyGen.generatePrivate(PK8KeySpec);
        System.out.println("Generated " + side + " private Key! Key: " + asHex(privateKey.getEncoded()) + "\n");

        return privateKey;
    }
    
    /**
     * 
     * @return
     */
    public static byte[] challenge() {
        // Cria array random de bytes e envia
        SecureRandom randomize = new SecureRandom();
        byte[] challenge = new byte[128];
        randomize.nextBytes(challenge);
        System.out.println("Challenge Done!\n");
        return challenge;
        }
    
    /**
     * 
     * @param clientKey
     * @param challenge
     * @return 
     * @throws java.security.SignatureException 
     * @throws java.security.InvalidKeyException 
     * @throws java.security.NoSuchAlgorithmException 
     */
    public static byte[] response(PrivateKey clientKey, byte[] challenge) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException{
        // Verifica veracidade da resposta      
        Signature signature = Signature.getInstance("SHA1withRSA");
        // Verifica com chave pública do cliente
        signature.initSign(clientKey);
        signature.update(challenge, 0, challenge.length);
        byte[] reply = signature.sign();
        return reply;
    }
    
    /**
     * 
     * @param clientPubKey
     * @param challenge
     * @param challengeReply
     * @return 
     * @throws java.security.InvalidKeyException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.SignatureException
     */
    public static boolean verifyResponse( PublicKey clientPubKey, byte[] challenge, byte[] challengeReply) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException{
        System.out.println("Resposta ao challenge recebida.");

        // Verifica veracidade da resposta      
        Signature signature = Signature.getInstance("SHA1withRSA");
        // Verifica com chave pública do cliente
        signature.initVerify(clientPubKey);
        signature.update(challenge, 0, challenge.length);

        // Como no tutorial 7 para verificar assinaturas
        boolean verifies = signature.verify(challengeReply);
        System.out.println("signature:" + verifies);
        return verifies;
    }
}
