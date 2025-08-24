package com.pki.example.service;

import org.springframework.stereotype.Service;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.UUID;
import com.pki.example.exception.KeyStoreOperationException;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

@Service
public class KeystoreService {

    @Value("${app.keystore.encryption-key}")
    private String globalKey;


    //Koristi se za CA sertifikate (ROOT, INTERMEDIATE)
    public void writeKeyPairAndCertificate(String keystoreFileName, char[] keystorePassword, String alias, PrivateKey privateKey, X509Certificate certificate) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, keystorePassword); // Inicijalizujemo novi, prazan keystore
            keyStore.setKeyEntry(alias, privateKey, keystorePassword, new Certificate[] {certificate});

            try (FileOutputStream fos = new FileOutputStream("keystores/" + keystoreFileName)) {
                keyStore.store(fos, keystorePassword);
            }

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new KeyStoreOperationException("Failed to write to keystore: " + keystoreFileName);
        }
    }

    //Koristi se za End-Entity sertifikate
    public void writeTrustedCertificate(String keystoreFileName, char[] keystorePassword, String alias, X509Certificate certificate) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, keystorePassword);

            keyStore.setCertificateEntry(alias, certificate);

            try (FileOutputStream fos = new FileOutputStream("keystores/" + keystoreFileName)) {
                keyStore.store(fos, keystorePassword);
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new KeyStoreOperationException("Failed to write trusted certificate to keystore: " + keystoreFileName);
        }
    }

    public PrivateKey readPrivateKey(String keystoreFileName, char[] keystorePassword, String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");

            try (FileInputStream fis = new FileInputStream("keystores/" + keystoreFileName)) {
                keyStore.load(fis, keystorePassword);
            }

            return (PrivateKey) keyStore.getKey(alias, keystorePassword); // Pretpostavljamo da je lozinka za ključ ista kao za keystore

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableKeyException e) {
            throw new KeyStoreOperationException("Failed to read private key from keystore: " + keystoreFileName);
        }
    }

    public X509Certificate readCertificate(String keystoreFileName, char[] keystorePassword, String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");

            try (FileInputStream fis = new FileInputStream("keystores/" + keystoreFileName)) {
                keyStore.load(fis, keystorePassword);
            }

            return (X509Certificate) keyStore.getCertificate(alias);

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new KeyStoreOperationException("Failed to read certificate from keystore: " + keystoreFileName);
        }

    }
    public String encryptPassword(char[] password, String userSymmetricKey) {
        try {
            // Pravimo SecretKey objekat od našeg stringa iz properties fajla
            SecretKey secretKey = new SecretKeySpec(userSymmetricKey.getBytes(StandardCharsets.UTF_8), "AES");

            // Inicijalizujemo Cipher za enkripciju
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // Enkripcija
            byte[] encryptedBytes = cipher.doFinal(new String(password).getBytes(StandardCharsets.UTF_8));

            // Enkriptovane bajtove pretvaramo u Base64 string, koji je bezbedan za čuvanje u bazi
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new KeyStoreOperationException("Failed to encrypt password.");
        }
    }

    public char[] decryptPassword(String encryptedPassword, String userSymmetricKey) {
        try {
            SecretKey secretKey = new SecretKeySpec(userSymmetricKey.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPassword);

            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            // Dekriptovane bajtove pretvaramo nazad u string i vraćamo kao char[]
            return new String(decryptedBytes, StandardCharsets.UTF_8).toCharArray();
        } catch (Exception e) {
            throw new KeyStoreOperationException("Failed to decrypt password.");
        }
    }

    public String encryptUserSymmetricKey(String userSymmetricKey) {
        try {
            SecretKey masterSecretKey = new SecretKeySpec(globalKey.getBytes(StandardCharsets.UTF_8), "AES");


            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, masterSecretKey);

            byte[] encryptedBytes = cipher.doFinal(userSymmetricKey.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(encryptedBytes);

        } catch (Exception e) {
            throw new KeyStoreOperationException("Failed to encrypt user symmetric key.");
        }
    }

    public String decryptUserSymmetricKey(String encryptedUserKey) {
        try {
            SecretKey masterSecretKey = new SecretKeySpec(globalKey.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, masterSecretKey);

            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedUserKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new KeyStoreOperationException("Failed to decrypt user symmetric key. Master key might be incorrect.");
        }
    }

    public char[] generateRandomPassword() {
        int length = 24;

        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";

        // Koristimo SecureRandom za kriptografski siguran izbor karaktera
        SecureRandom random = new SecureRandom();
        StringBuilder passwordBuilder = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            passwordBuilder.append(chars.charAt(random.nextInt(chars.length())));
        }

        // Vraćamo kao niz karaktera (char[]), što je malo sigurnije od čuvanja lozinke
        // kao nepromenljivog String objekta u memoriji.
        return passwordBuilder.toString().toCharArray();
    }

    }
