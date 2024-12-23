package unsa.security;

import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class Launch {

	public static void main(String[] args) {
        RBACSystem system = new RBACSystem();
        try {
			system.commandInterface();
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
				| InvalidAlgorithmParameterException | URISyntaxException e) {
			e.printStackTrace();
		}
	}
}
