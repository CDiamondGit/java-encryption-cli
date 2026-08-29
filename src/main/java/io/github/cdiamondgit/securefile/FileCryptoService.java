package io.github.cdiamondgit.securefile;

import java.nio.file.Path;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.SecretKeySpec;

public class FileCryptoService {

    public void encrypt(Path path, char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException { // throw the exceptions back to main
        byte[] saltBytes = generateSalt();
        SecretKey finalKey = generateAESKey(saltBytes, password);
        byte[] nonceBytes = generateNonce();
        
    }

    private byte[] generateSalt() { // random array of bytes are needed (salt), as password + salt -> hash
        SecureRandom secureRandom = new SecureRandom();
        byte[] saltBytes = new byte[16]; 

        secureRandom.nextBytes(saltBytes);
    
        return saltBytes;
    }

    private SecretKey generateAESKey(byte[] saltBytes, char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException { // if the SecretKeyFactory API cant get the algorithm, it is passed back to the method that called it
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, saltBytes, 210000, 256); // Password-Based Encryption Key Specification. It is a container that contains info about the key to be generated

        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // PBKDF... is the cryptographic method to be used to generate the AES key
            SecretKey derivedKey = secretKeyFactory.generateSecret(pbeKeySpec); // generate 256 bits of derived secret key material

            byte[] keyBytes = derivedKey.getEncoded(); // turn the derivedKey into a simple array of bytes
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES"); // It was not yet explicitly an AES key, so its bytes now will be wrapped in a SecretKeySpec configured for AES
            return secretKeySpec; // secretKeySpec is a type of SecretKey, except explicitly an AES key so it can be returned as a SecretKey
        } finally {
            pbeKeySpec.clearPassword(); // get rid of password data from memory
        }
    }

    private byte[] generateNonce() { // The nonce gives a unique starting value for each encryption so the same key does not reuse the same encryption stream
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonceBytes = new byte[12]; 

        return nonceBytes;
    }
}




