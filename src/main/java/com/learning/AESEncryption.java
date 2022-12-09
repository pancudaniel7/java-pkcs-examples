package com.learning;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Scanner;


public class AESEncryption {
    private static final String AES_CIPHER = "AES/ECB/PKCS5Padding";

    public static void createSoftHSMConfig(String hsmConfigFile, String hsmSharedLibraryFile) throws IOException {
        FileWriter fw = new FileWriter(hsmConfigFile);

        fw.write("name = SoftHSM\n" + "library = " + hsmSharedLibraryFile);
        fw.write("\n slot = 1632003794\n" + "attributes(generate, *, *) = {\n");
        fw.write("\t CKA_TOKEN = true\n}\n" + "attributes(generate, CKO_CERTIFICATE, *) = {\n");
        fw.write("\t CKA_PRIVATE = false\n}\n" + "attributes(generate, CKO_PUBLIC_KEY, *) = {\n");
        fw.write("\t CKA_PRIVATE = false\n}\n");
        fw.close();
    }

    public static void main(String[] args) {
        try {
            System.out.println("Enter the text to be encrypted: ");
            Scanner s = new Scanner(System.in);
            String inputText = s.nextLine();
            s.close();

            String configFile = "/tmp/softhsm.cfg";
            String hsmSharedLibFile = "/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so";
            createSoftHSMConfig(configFile, hsmSharedLibFile);

            Provider pkcs11Provider = Security.getProvider("SunPKCS11");
            pkcs11Provider = pkcs11Provider.configure(configFile);

            if (-1 == Security.addProvider(pkcs11Provider)) {
                throw new RuntimeException("could not add security provider");
            } else {
                System.out.println("provider initialized...");
            }

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
        } catch (Exception e) {
            e.printStackTrace();
        }
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