package com.pki.example.dto;

public class JwtResponse {
    private String token;
    private int expiresIn;

    public JwtResponse(String token, int expiresIn) {
        this.token = token;
        this.expiresIn = expiresIn;
    }

    public String getToken() {
        return token;
    }

    public int getExpiresIn() {
        return expiresIn;
    }
}
