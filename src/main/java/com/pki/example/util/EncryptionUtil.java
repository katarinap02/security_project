package com.pki.example.util;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class EncryptionUtil {

    /**
     * Enkriptuje plain text lozinku javnim ključem (PEM format).
     * @param password plain text lozinka
     * @param publicKeyPem javni ključ korisnika u PEM formatu
     * @return Base64 enkodovana šifrovana lozinka
     */
    public static String encryptPassword(String password, String publicKeyPem) throws Exception {
        // Ukloni PEM header/footer i whitespace
        String publicKeyContent = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        // Dekodiraj Base64 u bajtove
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyContent);

        // Napravi RSA PublicKey objekat
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(spec);

        // RSA enkripcija sa OAEP padding-om
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());

        // Vrati Base64 string
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}

