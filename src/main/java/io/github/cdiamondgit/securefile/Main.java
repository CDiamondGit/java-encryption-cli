package io.github.cdiamondgit.securefile;
import java.io.Console;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.Arrays;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Main {
    public static void main(String[] args) {
        String file;
        Path path;

        if (args.length == 0) {
            System.out.println("Error: No arguments passed");
            return;
        }

        if (args[0].equals("encrypt") || args[0].equals("decrypt")) {
            if (args.length > 2) {
                System.out.println("Error: Too many arguments passed");
                return;
            } else if (args.length == 1) {
                System.out.println("Error: No file given");
                return;
            } else {
                file = args[1];
            }
        } else {
            System.out.println("Error: Incorrect command");
            return;
        }

        path = Path.of(file);

        if (Files.notExists(path)) {
            System.out.println("Error: File does not exist");
            return;
        } else if (!(Files.isRegularFile(path))){
            System.out.println("Error: File is not a regular file");
            return;
        }


        if (args[0].equals("encrypt")) {
            FileCryptoService fileCryptoService = new FileCryptoService();
            Console console = System.console();

            if (console == null) {
                System.out.println("Error: Console could not be accessed");
                return;
            }

            char[] password; // a String is immutable, so an array of characters is used to overwrite the password once finished
            password = console.readPassword("Password: ");

            if (password == null) {
                System.out.println("Error: Password could not be read");
                return;
            }

            try {
                fileCryptoService.encrypt(path, password);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                System.out.println("Error: Cryptographic operation failed: " + e);
            } finally {
                Arrays.fill(password, '\0'); // whether fileCryptoService runs or not, the password will be wiped from memory
            }
            

        
        } else if (args[0].equals("decrypt")) {

        }

    }
}