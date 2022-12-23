package com.examples;

import com.examples.config.SoftHSMConfigProvider;
import com.examples.provider.PKCS11SunSecurityProvider;
import com.examples.provider.SecurityProvider;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Date;
import java.util.Scanner;

public class RSASigning {

    private static final SecurityProvider securityProvider;

    private static final String KEY_ALIAS = "key3";

    static {
        String configFilePath = "/tmp/softhsm.cfg";
        String hsmSharedLibFilePath = "/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so";

        String softhsmSlotNumber = "765320209";
        securityProvider = new PKCS11SunSecurityProvider(new SoftHSMConfigProvider(), configFilePath, hsmSharedLibFilePath, softhsmSlotNumber);
    }

    private static X509Certificate generateCertificate(KeyPair keyPair) throws CertificateEncodingException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
        certificateGenerator.setSerialNumber(BigInteger.valueOf(1));   //or generate a random number
        certificateGenerator.setSubjectDN(new X509Principal("CN=localhost"));  //see examples to add O,OU etc
        certificateGenerator.setIssuerDN(new X509Principal("CN=localhost")); //same since it is self-signed
        certificateGenerator.setPublicKey(keyPair.getPublic());
        certificateGenerator.setNotBefore(new Date());

        ZonedDateTime afterDate = LocalDate.now().plusYears(20L).atStartOfDay(ZoneId.systemDefault());
        certificateGenerator.setNotAfter(Date.from(afterDate.toInstant()));
        certificateGenerator.setSignatureAlgorithm("SHA256withRSA");

        return certificateGenerator.generate(keyPair.getPrivate());
    }

    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        Provider pkcs11Provider = securityProvider.getInstance();

        char[] pin = "1234".toCharArray();
        KeyStore keyStore;

        keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
        keyStore.load(null, pin);

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, "1234".toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(KEY_ALIAS);

        if (privateKey == null && certificate == null) {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", pkcs11Provider);
            gen.initialize(2048);
            KeyPair keyPair = gen.generateKeyPair();

            privateKey = keyPair.getPrivate();
            certificate = generateCertificate(keyPair);
            keyStore.setKeyEntry(KEY_ALIAS, privateKey, "1234".toCharArray(), new X509Certificate[]{certificate});
        }

        System.out.println("Enter the text to be sign: ");
        Scanner s = new Scanner(System.in);
        String inputText = s.nextLine();
        s.close();

        Signature singingObj = Signature.getInstance("SHA256withRSA", pkcs11Provider);

        singingObj.initSign(privateKey);
        singingObj.update(inputText.getBytes(StandardCharsets.UTF_8));

        byte[] digitalSignature = singingObj.sign();

        System.out.println("Signature data: " + Arrays.toString(digitalSignature));
        System.out.println("Verify signature...");

        Signature verifySingingObj = Signature.getInstance("SHA256withRSA", pkcs11Provider);

        verifySingingObj.initVerify(certificate.getPublicKey());
        verifySingingObj.update(inputText.getBytes(StandardCharsets.UTF_8));
        boolean isValid = verifySingingObj.verify(digitalSignature);

        String isValidResponse = isValid ? "valid" : "invalid";
        System.out.println("The signature is " + isValidResponse);
    }
}
