package io.github.cdiamondgit.securefile;

import java.nio.file.Path;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.io.IOException;
import java.nio.file.Files;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import java.nio.ByteBuffer;

public class FileCryptoService {
    private static final byte[] MAGIC_BYTES = {'S', 'E', 'C', 'F'};
    private static final byte VERSION = 1;
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;

    public void encrypt(Path path, char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,BadPaddingException { // throw the exceptions back to main
        byte[] saltBytes = generateSalt();
        SecretKey AESkey = generateAESKey(saltBytes, password);
        byte[] nonceBytes = generateNonce(); 

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // create cipher encryption engine 
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, nonceBytes); // The 128 bit GCM authentication tag verifies that the ciphertext has not been altered and that the correct key and nonce were used
        cipher.init(Cipher.ENCRYPT_MODE, AESkey, gcmParameterSpec); 

        byte[] fileBytes = Files.readAllBytes(path);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);

        Path outputPath = path.resolveSibling(path.getFileName().toString() + ".sec"); // this makes a new path leading to beside the old file, with the ".sec" extension

        int totalSize = MAGIC_BYTES.length + Byte.BYTES + SALT_BYTES + NONCE_BYTES + encryptedBytes.length;

        ByteBuffer buffer = ByteBuffer.allocate(totalSize);
        buffer.put(MAGIC_BYTES);
        buffer.put(VERSION);
        buffer.put(saltBytes);
        buffer.put(nonceBytes);
        buffer.put(encryptedBytes);

        Files.write(outputPath, buffer.array());
    }

    private byte[] generateSalt() { // random array of bytes are needed (salt), as password + salt -> hash
        SecureRandom secureRandom = new SecureRandom();
        byte[] saltBytes = new byte[SALT_BYTES]; 

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
        byte[] nonceBytes = new byte[NONCE_BYTES]; 

        secureRandom.nextBytes(nonceBytes);

        return nonceBytes;
    }
}




