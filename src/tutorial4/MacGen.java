/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tutorial4;

/**
 *
 * @author chico
 */
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
 
public class MacGen{
    public static byte[] GenerateMAC(byte[] message, SecretKeySpec key) {
        byte[] digest = null;
        try {
            // create a MAC and initialize with the above key
            Mac mac = Mac.getInstance(key.getAlgorithm());
            mac.init(key);
            // create a digest from the byte array
            digest = mac.doFinal(message);

        } catch (Exception e) { e.printStackTrace(); }
        
        return digest;
    }
}