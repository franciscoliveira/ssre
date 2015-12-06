package trunk;


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Miguel
 */
public class GenerateKey {
    private static void saveKey(SecretKey key, String alias)
    {
        // command line : keytool -list -keystore novaks.jks -storetype JCEKS
        try
        {
            FileInputStream input = null;
            char[] password = null;
            try
            {
                input = new FileInputStream("novaks.jks");
                password = "password".toCharArray();
            } catch(FileNotFoundException fe)
            {
                System.out.println(fe.getMessage());
            }
            
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(input, password); 
            
            ks.setKeyEntry(alias, key,"password".toCharArray(),null);
            
            FileOutputStream writeStream = new FileOutputStream("novaks.jks");
            ks.store(writeStream, "password".toCharArray());
            writeStream.close();
            
        } catch (Exception e)
        {
            e.printStackTrace();
        }
    }
    
    public static SecretKey retrieveKey(String alias)
    {
        try
        {
            FileInputStream input = new FileInputStream("novaks.jks");
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(input,"password".toCharArray());
            SecretKey sk = (SecretKey) ks.getKey(alias, "password".toCharArray());
            return sk;
        } catch (Exception e)
        {
            System.err.println(e.getMessage());
        }
        return null;
    }
    
    public static void generateKey(String alias)
    {
            try{
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            SecretKey sk = kg.generateKey();
            GenerateKey.saveKey(sk, alias);
            } catch (Exception e)
            {
            System.err.println(e.getMessage());
            }
            
    } 
    
    public static SecretKey generateSessionKey()
    {
        try
        {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            SecretKey sk = kg.generateKey();
            return sk;
        } catch (Exception e)
        {
            System.err.println(e.getMessage());
        }
        return null;
    }
}
