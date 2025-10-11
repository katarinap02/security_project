package com.pki.example.util;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.Duration;
import java.util.Base64;

public class TotpTestUtil {

    public static String generateCurrentCode(String base32Secret) throws Exception {
        // Dekoduj secret iz baze (ako ga čuvaš kao Base32 string, npr. "SM6D53RRV5CZIG3ES6TKLZJV2ON3XX7N")
        byte[] keyBytes = new org.apache.commons.codec.binary.Base32().decode(base32Secret);
        SecretKey key = new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA1");

        // Standardni Google Authenticator kod radi sa 30 sekundi intervalom
        TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30));

        // Generiši kod za trenutno vreme
        int otp = totp.generateOneTimePassword(key, Instant.now());

        return String.format("%06d", otp); // formatiraj na 6 cifara
    }
}
