package com.pki.example.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;

public class TwoFAService {
    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    // pozoveš kada korisnik uključi 2FA
    public String setup2FA(String userEmail) {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        String secret = key.getKey(); // čuvaš u bazi za korisnika

        // URL za QR kod
        String qrUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL("SecurityApp", userEmail, key);

        // možeš frontend-u poslati i secret i qrUrl
        return qrUrl;
    }

    // pozoveš pri loginu kada korisnik unese kod
    public boolean verifyCode(String secret, int code) {
        return gAuth.authorize(secret, code);
    }
}
