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

    public static void main(String[] args) throws Exception {  // 메인 함수 시작
        Scanner scanner = new Scanner(System.in);  // 사용자 입력을 받기 위한 Scanner 객체 생성

        System.out.println("Please enter the website link:");  // 사용자에게 웹사이트 링크 입력 요청 메시지 출력
        String website = scanner.nextLine();  // 웹사이트 링크를 입력받음

        System.out.println("Please enter the username:");  // 사용자에게 아이디 입력 요청 메시지 출력
        String username = scanner.nextLine();  // 아이디를 입력받음

        // writeCredentialsToFile 함수를 호출하여 웹사이트, 아이디, 비밀번호를 파일에 저장하고, 이 결과로 해시된 비밀번호를 반환받음
        String hashedPassword = writeCredentialsToFile(username, "MyPassword", website, "C:\\Users\\username\\password\\my_account_list.txt");

        // 결과 출력
        System.out.println("Website: " + website);
        System.out.println("Username: " + username);
        System.out.println("Your hashed password is: " + hashedPassword);
    }

    private static String writeCredentialsToFile(String username, String password, String website, String filename) throws Exception {
        SecureRandom sr = new SecureRandom();  // 랜덤값 생성을 위한 SecureRandom 객체 생성
        byte[] salt = new byte[16];  // 16바이트 배열 생성
        sr.nextBytes(salt);  // 랜덤 salt 생성

        // PBKDF2WithHmacSHA1 알고리즘을 이용하여 비밀번호를 해시
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = factory.generateSecret(spec).getEncoded();
        String hashedPassword = toHex(hash);  // 해시된 비밀번호를 16진수 문자열로 변환

        // 파일에 쓸 내용을 준비
        List<String> lines = new ArrayList<>();
        lines.add("Website: " + website);
        lines.add("Username: " + username);
        lines.add("Hashed Password: " + hashedPassword);
        lines.add("---------------------------------------------------------------------------------");
        
        // 준비한 내용을 파일에 쓰기 (기존 내용은 유지하고 새로운 내용을 추가)
        Files.write(Paths.get(filename), lines, StandardCharsets.UTF_8, StandardOpenOption.APPEND);

        return hashedPassword;  // 해시된 비밀번호 반환
    }

    private static String toHex(byte[] array) throws NoSuchAlgorithmException {
        // 바이트 배열을 16진수 문자열로 변환
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
