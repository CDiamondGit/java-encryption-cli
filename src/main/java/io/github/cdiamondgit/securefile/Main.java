package io.github.cdiamondgit.securefile;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException; // covers NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, AEADBadTagException
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        String file;
        Path path;

        if (args.length == 0) {
            System.out.println("\nError: No arguments passed\n");
            return;
        }

        if (args[0].equals("encrypt") || args[0].equals("decrypt")) {
            if (args.length > 2) {
                System.out.println("Error: Too many arguments passed\n");
                return;
            } else if (args.length == 1) {
                System.out.println("Error: No file given\n");
                return;
            } else {
                file = args[1];
            }
        } else {
            System.out.println("Error: Incorrect command\n");
            return;
        }

        path = Path.of(file);

        if (Files.notExists(path)) {
            System.out.println("Error: File does not exist\n");
            return;
        } else if (!(Files.isRegularFile(path))){
            System.out.println("Error: File is not a regular file\n");
            return;
        }


        if (args[0].equals("encrypt")) {
            FileCryptoService fileCryptoService = new FileCryptoService();
            Console console = System.console();

            if (console == null) {
                System.out.println("Error: Console could not be accessed\n");
                return;
            }

            char[] password; // a String is immutable, so an array of characters is used to overwrite the password once finished
            password = console.readPassword("Password: ");

            if (password == null) {
                System.out.println("Error: Password could not be read\n");
                return;
            }

            try {
                fileCryptoService.encrypt(path, password);
            } catch (GeneralSecurityException | IOException e) {
                System.out.println("Error: Cryptographic operation failed: " + e.getMessage() + "\n");
            } finally {
                Arrays.fill(password, '\0'); // whether fileCryptoService runs or not, the password will be wiped from memory
            }

        } else if (args[0].equals("decrypt")) {
            FileCryptoService fileCryptoService = new FileCryptoService();
            Console console = System.console();

            if (console == null) {
                System.out.println("Error: Console could not be accessed\n");
                return;
            }

            char[] password; // a String is immutable, so an array of characters is used to overwrite the password once finished
            password = console.readPassword("Password: ");

            if (password == null) {
                System.out.println("Error: Password could not be read\n");
                return;
            }

            try {
                fileCryptoService.decrypt(path, password);
            } catch (GeneralSecurityException | IOException e) {
                System.out.println("Error: Cryptographic operation failed: " + e.getMessage() + "\n");
            } finally {
                Arrays.fill(password, '\0'); // whether fileCryptoService runs or not, the password will be wiped from memory
            }
        }
    }
}