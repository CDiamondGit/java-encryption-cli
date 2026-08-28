package io.github.cdiamondgit.securefile;
import java.nio.file.Path;
import java.nio.file.Files;

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

        } else if (args[0].equals("decrypt")) {

        }

    }
}