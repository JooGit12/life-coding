package com.kim.hashpassword0214;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Main {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Please enter the website link:");
        String website = scanner.nextLine();

        System.out.println("Please enter the username:");
        String username = scanner.nextLine();

        String hashedPassword = writeCredentialsToFile(username, "MyPassword", website, "C:\\Users\\kjww9\\password\\my_account_list.txt");

        System.out.println("Website: " + website);
        System.out.println("Username: " + username);
        System.out.println("Your hashed password is: " + hashedPassword);
    }

    private static String writeCredentialsToFile(String username, String password, String website, String filename) throws Exception {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);  // Create a random salt

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = factory.generateSecret(spec).getEncoded();
        String hashedPassword = toHex(hash);

        List<String> lines = new ArrayList<>();
        lines.add("Website: " + website);
        lines.add("Username: " + username);
        lines.add("Hashed Password: " + hashedPassword);
        lines.add("---------------------------------------------------------------------------------");
        
        Files.write(Paths.get(filename), lines, StandardCharsets.UTF_8, StandardOpenOption.APPEND);  // Append to the file

        return hashedPassword;
    }

    private static String toHex(byte[] array) throws NoSuchAlgorithmException {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0) {
            return String.format("%0"  +paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }
}
