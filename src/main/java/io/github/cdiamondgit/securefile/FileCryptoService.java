package io.github.cdiamondgit.securefile;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException; // covers NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, AEADBadTagException
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class FileCryptoService {
    private static final byte[] MAGIC_BYTES = {'S', 'E', 'C', 'F'};
    private static final byte VERSION = 1;
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;

    public void encrypt(Path path, char[] password) throws GeneralSecurityException, IOException { // throw the exceptions back to main

        byte[] saltBytes = generateSalt();
        SecretKey AESkey = generateAESKey(saltBytes, password);
        byte[] nonceBytes = generateNonce();

        System.out.println("Encrypting...\n");

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

        String originalFileSize = formatFileSize(Files.size(path));
        String newFileSize = formatFileSize(Files.size(outputPath));

        System.out.println("Input: " + path.getFileName().toString() + " (" + originalFileSize + ")");
        System.out.println("Output: " + outputPath.getFileName().toString() + " (" + newFileSize + ")");

        System.out.println("\nEncryption successful\n");
    }

    public void decrypt(Path path, char[] password) throws GeneralSecurityException, IOException { // throw the exceptions back to main
        byte[] readBytes = Files.readAllBytes(path);
        int minimumSize = MAGIC_BYTES.length + Byte.BYTES + SALT_BYTES + NONCE_BYTES + 16; // 16 as the GCM tag is 16 bytes (128 / 8)
        if (readBytes.length < minimumSize) {
            System.out.println("\nError: Invalid encrypted file\n");
            return;
        }

        ByteBuffer buffer = ByteBuffer.wrap(readBytes);

        byte[] readMagicBytes = new byte[MAGIC_BYTES.length];
        byte[] readSaltBytes = new byte[SALT_BYTES];
        byte[] readNonceBytes = new byte[NONCE_BYTES];
        byte readVersion;

        buffer.get(readMagicBytes); // store the magic bytes in the array AND move the buffer's position forward by the number of bytes
        readVersion = buffer.get();

        if (Arrays.equals(MAGIC_BYTES, readMagicBytes) && (VERSION == readVersion)) {
            buffer.get(readSaltBytes);
            buffer.get(readNonceBytes);
            byte[] readFileContentsAndTag = new byte[buffer.remaining()];
            buffer.get(readFileContentsAndTag);

            SecretKey recreatedAESkey = generateAESKey(readSaltBytes, password); // The same AES key is created from the password and salt bytes
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); 
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, readNonceBytes); // The 128 bit GCM authentication tag verifies that the ciphertext has not been altered and that the correct key and nonce were used

            cipher.init(Cipher.DECRYPT_MODE, recreatedAESkey, gcmParameterSpec); 

            System.out.println("Decrypting...\n");

            byte[] decryptedBytes = cipher.doFinal(readFileContentsAndTag);
            String inputFileName = path.getFileName().toString();
            String outputName = fileNameHandler(inputFileName, path);
            Path outputPath = path.resolveSibling(outputName);

            Files.write(outputPath, decryptedBytes);

            String originalFileSize = formatFileSize(Files.size(path));
            String newFileSize = formatFileSize(Files.size(outputPath));

            System.out.println("Input: " + path.getFileName().toString() + " (" + originalFileSize + ")");
            System.out.println("Output: " + outputPath.getFileName().toString() + " (" + newFileSize + ")");

            System.out.println("\nDecryption successful\n");
        } else {
            System.out.println("\nError: Could not open encrypted file\n");
            return;
        }
    }

    private byte[] generateSalt() { // random array of bytes are needed (salt), as password + salt -> hash
        SecureRandom secureRandom = new SecureRandom();
        byte[] saltBytes = new byte[SALT_BYTES]; 

        secureRandom.nextBytes(saltBytes);

        return saltBytes;
    }

    private SecretKey generateAESKey(byte[] saltBytes, char[] password) throws GeneralSecurityException { // if the SecretKeyFactory API cant get the algorithm, it is passed back to the method that called it
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, saltBytes, 600000, 256); // Password-Based Encryption Key Specification. It is a container that contains info about the key to be generated

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

    private static String formatFileSize(long bytes) {
        if (bytes >= 1000 * 1000 * 1000) {
            return String.format("%.1f GB", bytes / (1000.0 * 1000 * 1000));
        } else if (bytes >= 1000 * 1000) {
            return String.format("%.1f MB", bytes / (1000.0 * 1000));
        } else if (bytes >= 1000) {
            return String.format("%.1f KB", bytes / 1000.0);
        } else {
            return bytes + " bytes";
        }
    }


    private String fileNameHandler(String inputFileName, Path path) {
        String outputName;
        if (inputFileName.endsWith(".sec")) {
            outputName = inputFileName.substring(0, inputFileName.length() - ".sec".length()); // remove .sec from the encrypted file name
        } else {
            outputName = path.getFileName().toString(); // otherwise just take the same name as the file 
        }

        Path outputPath = path.resolveSibling(outputName);

        if (outputName.indexOf('.') != -1) { // if the file has an extension
            String outputFileExtension = outputName.substring(outputName.lastIndexOf('.'),outputName.length());
            String outputFileMinusExtension = outputName.substring(0,outputName.lastIndexOf('.'));


            int i = 1;
            while (Files.exists(outputPath)) {
                outputName = outputFileMinusExtension + " (" + i + ")" + outputFileExtension.toString();
                outputPath = path.resolveSibling(outputName);
                i++;
            }
        } else { // if the file does not have an extension
            String outputFileOriginalName = outputName;
            int i = 1;
            while (Files.exists(outputPath)) {
                outputName = outputFileOriginalName + " (" + i + ")" ;
                outputPath = path.resolveSibling(outputName);
                i++;
            }
        }
        return outputName;
    }
}