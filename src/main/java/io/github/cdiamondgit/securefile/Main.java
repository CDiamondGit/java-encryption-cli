package io.github.cdiamondgit.securefile;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException; // covers NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, AEADBadTagException
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("\nError: No arguments passed\n");
            return;
        }

        if(!(args[0].equals("encrypt")) && !(args[0].equals("decrypt" ))) {
            System.out.println("Error: Incorrect command\n");
            return;
        }

        if (args.length > 2) {
            System.out.println("Error: Too many arguments passed\n");
            return;
        }

        if (args.length == 1) {
            System.out.println("Error: No file given\n");
            return;
        } 
        
        String file = args[1];
        Path path = Path.of(file);

        if (Files.notExists(path)) {
            System.out.println("Error: File does not exist\n");
            return;
        } 
        
        if (!(Files.isRegularFile(path))){
            System.out.println("Error: File is not a regular file\n");
            return;
        }

        Console console = System.console();

        if (console == null) {
            System.out.println("Error: Console could not be accessed\n");
            return;
        }
        
        char[] password = console.readPassword("Password: "); // a String is immutable, so an array of characters is used to overwrite the password once finished

        if (password == null) {
            System.out.println("Error: Password could not be read\n");
            return;
        }

        FileCryptoService fileCryptoService = new FileCryptoService();
        
        try {
            if (args[0].equals("encrypt")) {
                fileCryptoService.encrypt(path, password);
            } else {
                fileCryptoService.decrypt(path, password);
            }
        } catch (GeneralSecurityException | IOException e) {
            System.out.println("Error: Cryptographic operation failed: " + e.getMessage() + "\n");
        } finally {
            Arrays.fill(password, '\0'); // whether fileCryptoService runs or not, the password will be wiped from memory
        }
    }
}