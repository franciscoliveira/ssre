/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tutorial2;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author chico
 */
public class Decryption {
    	public static void main(String[] args) {

            try {
		// raw key material, for testing purposes
		byte[] keyBytes = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
		
		// Converts raw key into SecretKey object
		// should be replaced by key generation
		SecretKeySpec key = new SecretKeySpec(keyBytes, "RC4");
	
		// decryption
		Cipher decipher = Cipher.getInstance("RC4");
		decipher.init(Cipher.DECRYPT_MODE, key);
		
		// read data from encrypted file
		FileInputStream cipherfis = new FileInputStream("output");
		byte[] cipherdata = new byte[cipherfis.available()];
		cipherfis.read(cipherdata);
		cipherfis.close();
		
		// decrypt
		byte[] plain = decipher.doFinal(cipherdata);
		
		// write plain to file
		FileOutputStream plainfos = new FileOutputStream("recover");
		plainfos.write(plain);
		plainfos.close();
            } catch (Exception e){ e.printStackTrace(); }
               
       }
}