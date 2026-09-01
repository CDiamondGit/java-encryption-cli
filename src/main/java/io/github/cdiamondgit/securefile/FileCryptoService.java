package io.github.cdiamondgit.securefile;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException; // covers NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, AEADBadTagException
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
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
    private static final int BUFFER_SIZE = 8192;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_TAG_BYTES = 16;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int ITERATION_COUNT = 600000;


    public void encrypt(Path path, char[] password) throws GeneralSecurityException, IOException { // throw the exceptions back to main
        byte[] saltBytes = generateSalt();
        SecretKey AESkey = generateAESKey(saltBytes, password);
        byte[] nonceBytes = generateNonce();

        System.out.println("Encrypting...\n");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // create cipher encryption engine 
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_BITS, nonceBytes); // The 128 bit GCM authentication tag verifies that the ciphertext has not been altered and that the correct key and nonce were used
        cipher.init(Cipher.ENCRYPT_MODE, AESkey, gcmParameterSpec); 

        long originalFileSizeBytes = Files.size(path);
        long encryptedFileSizeBytes = originalFileSizeBytes + MAGIC_BYTES.length + Byte.BYTES + SALT_BYTES + NONCE_BYTES + GCM_TAG_BYTES; 

        String outputName = fileNameHandler(path.getFileName().toString(), path, true);
        Path outputPath = path.resolveSibling(outputName); // this makes a new path leading to beside the old file, with the ".sec" extension

        try (InputStream inputStream = Files.newInputStream(path); OutputStream outputStream = Files.newOutputStream(outputPath)) { // make an input and output stream for each file (the try loop will close them afterwards)
            int totalSizeHeaders = MAGIC_BYTES.length + Byte.BYTES + SALT_BYTES + NONCE_BYTES;
            ByteBuffer buffer = ByteBuffer.allocate(totalSizeHeaders);

            buffer.put(MAGIC_BYTES);
            buffer.put(VERSION);
            buffer.put(saltBytes);
            buffer.put(nonceBytes);

            outputStream.write(buffer.array()); // write headers to beginning of encrypted file
            processStream(inputStream, outputStream, cipher, originalFileSizeBytes);

            byte[] finalBytes = cipher.doFinal(); // write the authentication tag
            outputStream.write(finalBytes); 
        }

        String formattedOriginalFileSizeBytes = formatFileSize(originalFileSizeBytes);
        String formattedEncrypedFileSizeBytes = formatFileSize(encryptedFileSizeBytes);

        System.out.println("\n\nInput: " + path.getFileName() + " (" + formattedOriginalFileSizeBytes + ")");
        System.out.println("Output: " + outputPath.getFileName() + " (" + formattedEncrypedFileSizeBytes + ")");
        System.out.println("\nEncryption successful\n");
    }


    public void decrypt(Path path, char[] password) throws GeneralSecurityException, IOException { // throw the exceptions back to main
        try (InputStream inputStream = Files.newInputStream(path)) {
            int totalSizeHeadersAndTag = MAGIC_BYTES.length + Byte.BYTES + SALT_BYTES + NONCE_BYTES + GCM_TAG_BYTES; 

            if (Files.size(path) < totalSizeHeadersAndTag) {
                System.out.println("\nError: Invalid encrypted file\n");
                return;
            }

            byte[] readMagicBytes = inputStream.readNBytes(MAGIC_BYTES.length); 
            byte readVersion = (byte) inputStream.read();

            if (Arrays.equals(MAGIC_BYTES, readMagicBytes) && (VERSION == readVersion)) {
                String inputFileName = path.getFileName().toString();
                String outputName = fileNameHandler(inputFileName, path, false);

                long encryptedFileSizeBytes = Files.size(path);
                long decryptedFileSizeBytes = encryptedFileSizeBytes - MAGIC_BYTES.length - Byte.BYTES - SALT_BYTES - NONCE_BYTES - GCM_TAG_BYTES; 

                Path outputPath = path.resolveSibling(outputName);

                byte[] readSaltBytes = inputStream.readNBytes(SALT_BYTES);
                byte[] readNonceBytes = inputStream.readNBytes(NONCE_BYTES);

                SecretKey recreatedAESkey = generateAESKey(readSaltBytes, password); // The same AES key is created from the password and salt bytes
                
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_BITS, readNonceBytes); // The 128 bit GCM authentication tag verifies that the ciphertext has not been altered and that the correct key and nonce were used
                cipher.init(Cipher.DECRYPT_MODE, recreatedAESkey, gcmParameterSpec);

                System.out.println("Decrypting...\n");

                Path tempPath = Files.createTempFile(outputPath.toAbsolutePath().getParent(),"securefile-",".tmp"); // temporary file to write to until the tag is verified at the end of the file

                try {
                    try (OutputStream outputStream = Files.newOutputStream(tempPath)) {
                        processStream(inputStream, outputStream, cipher, encryptedFileSizeBytes - totalSizeHeadersAndTag + GCM_TAG_BYTES);
                        System.out.println("\n\nAuthenticating file...");
                        try {
                            byte[] finalBytes = cipher.doFinal(); // verifies the authentication tag
                            outputStream.write(finalBytes); //authentication succeeded
                        } catch (AEADBadTagException e) { 
                            System.out.println("\nError: Authentication failed. Incorrect password or corrupted file.\n");
                            return; // authentication failed
                        }
                    }
                    Files.move(tempPath, outputPath); // move the temporary file to the final output path

                } finally {
                    Files.deleteIfExists(tempPath); // Remove the temporary file if it still exists
                }

                String formattedEncryptedFileSizeBytes = formatFileSize(encryptedFileSizeBytes);
                String formattedDecryptedFileSizeBytes = formatFileSize(decryptedFileSizeBytes);

                System.out.println("\nInput: " + path.getFileName() + " (" + formattedEncryptedFileSizeBytes + ")");
                System.out.println("Output: " + outputPath.getFileName() + " (" + formattedDecryptedFileSizeBytes + ")");
                System.out.println("\nDecryption successful\n");
            } else {
                System.out.println("\nError: Could not open encrypted file\n");
                return;
            }
        }
    }

    private byte[] generateSalt() { // random array of bytes are needed (salt), as password + salt -> hash
        SecureRandom secureRandom = new SecureRandom();
        byte[] saltBytes = new byte[SALT_BYTES]; 

        secureRandom.nextBytes(saltBytes);
        return saltBytes;
    }


    private SecretKey generateAESKey(byte[] saltBytes, char[] password) throws GeneralSecurityException { // if the SecretKeyFactory API cant get the algorithm, it is passed back to the method that called it
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, saltBytes, ITERATION_COUNT, KEY_LENGTH_BITS); // Password-Based Encryption Key Specification. It is a container that contains info about the key to be generated

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


    private String fileNameHandler(String inputFileName, Path path, boolean encrypting) {
        String outputName;

        if (encrypting) {
            outputName = inputFileName + ".sec";
        } else if (inputFileName.endsWith(".sec")) {
            outputName = inputFileName.substring(0, inputFileName.length() - ".sec".length());
        } else {
            outputName = path.getFileName().toString();
        }

        Path outputPath = path.resolveSibling(outputName);

        if (outputName.indexOf('.') != -1) { // if the file has an extension
            String outputFileExtension = outputName.substring(outputName.lastIndexOf('.'),outputName.length());
            String outputFileMinusExtension = outputName.substring(0,outputName.lastIndexOf('.'));

            int i = 1;
            while (Files.exists(outputPath)) {
                outputName = outputFileMinusExtension + " (" + i + ")" + outputFileExtension;
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


    private void processStream(InputStream inputStream, OutputStream outputStream, Cipher cipher, long totalInputBytes) throws GeneralSecurityException, IOException {
        byte[] fileBuffer = new byte[BUFFER_SIZE]; // Read the file in chunks so large files do not need to be loaded fully into memory
        int currentBytesRead;
        long totalBytesRead = 0;

        char[] progressBar = new char[20];

        while ((currentBytesRead = inputStream.read(fileBuffer)) != -1) { // currentBytesRead stores how many bytes were read into the buffer as the end of the file will not fill up the buffer fully (EOF == -1)
            byte[] processingChunk = cipher.update(fileBuffer, 0, currentBytesRead);

            if (processingChunk != null) {
                outputStream.write(processingChunk);
            }

            totalBytesRead += currentBytesRead;
            long percentageDone = (totalBytesRead * 100) / totalInputBytes;

            for (int i = 0; i < progressBar.length; i++) {
                if (i < percentageDone / 5) {
                    progressBar[i] = '#';
                } else {
                    progressBar[i] = '-';
                }
            }

            System.out.print("\r[" + new String(progressBar) + "] " + percentageDone + "%"); // progressBar (char[]) --> progressBar (String)
        }
    }
}