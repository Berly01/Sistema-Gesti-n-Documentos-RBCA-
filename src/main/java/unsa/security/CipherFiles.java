package unsa.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class CipherFiles {

	SecretKey secretKey;
	Cipher cipher;
	GCMParameterSpec parameterSpec;
	
	public CipherFiles() throws NoSuchAlgorithmException, NoSuchPaddingException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // Usa 128, 192 o 256 bits según sea necesario
        secretKey = keyGen.generateKey();
        
        // Configuración para AES-GCM
        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12]; // GCM usa un IV de 12 bytes
        new java.security.SecureRandom().nextBytes(iv);
        parameterSpec = new GCMParameterSpec(128, iv);
	}
	
	public byte[] cipher(String text) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] encrypted = cipher.doFinal(text.getBytes());  
        
        return encrypted;
	}
	
	public static void saveData(byte[] encrypted, String fileName) throws IOException {
		Files.write(Paths.get(fileName + ".bin"), encrypted);
	}
	
	public static byte[] loadData(String fileName) throws IOException 
	{		
		byte[] originalData = Files.readAllBytes(Paths.get(fileName + ".bin"));
		return originalData;
	}
	
	public String decipher(byte[] encrypted) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
       
        return new String(decrypted);
	}
	   
	

	
}






