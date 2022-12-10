package com.examples;

import com.examples.config.SoftHSMConfigProvider;
import com.examples.provider.PKCS11SunSecurityProvider;
import com.examples.provider.SecurityProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Scanner;


public class AESEncryption {

    private static SecurityProvider securityProvider;

    static {
        String configFilePath = "/tmp/softhsm.cfg";
        String hsmSharedLibFilePath = "/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so";

        securityProvider = new PKCS11SunSecurityProvider(new SoftHSMConfigProvider(), configFilePath, hsmSharedLibFilePath, "1632003794");
    }

    private static final String AES_CIPHER = "AES/ECB/PKCS5Padding";

    public static void main(String[] args) throws Exception {
            System.out.println("Enter the text to be encrypted: ");
            Scanner s = new Scanner(System.in);
            String inputText = s.nextLine();
            s.close();

            Provider pkcs11Provider = securityProvider.getInstance();

            Security.addProvider(pkcs11Provider);
            char[] pin = "1234".toCharArray();
            KeyStore keyStore;

            keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
            keyStore.load(null, pin);

            SecretKeySpec secretKeySpec = new SecretKeySpec("0123456789ABCDEF".getBytes(), 0, 16, "AES");
            Key key = new SecretKeySpec(secretKeySpec.getEncoded(), 0, 16, "AES");

            keyStore.setKeyEntry("AA", key, "1234".toCharArray(), null);
            keyStore.store(null);

            SecretKey key1 = (SecretKey) keyStore.getKey("AA", "1234".toCharArray());
            System.out.println("the algorithm: " + key1.getAlgorithm() + ", the key: " + key1 + ", format: " + key1.serialVersionUID);

            String encryptedString = performEncryption(key1, inputText);
            System.out.println("encryptedString: " + encryptedString);

            String decryptedText = performDecryption(key1, encryptedString);
            System.out.println("decryptedString: " + decryptedText);
    }

    private static String performEncryption(Key secretKey, String inputText) throws Exception {
        Cipher cipher;
        String encryptedText;
        cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] cipherText = cipher.doFinal(inputText.getBytes(StandardCharsets.UTF_8));
        encryptedText = java.util.Base64.getEncoder().encodeToString(cipherText);
        return encryptedText;
    }

    private static String performDecryption(Key key, String encryptedString) throws Exception {
        Cipher cipher;
        cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] deciphered = cipher.doFinal(java.util.Base64.getDecoder().decode(encryptedString));
        return new String(deciphered);
    }
}