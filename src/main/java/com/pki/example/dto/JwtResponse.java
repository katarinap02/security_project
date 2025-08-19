package com.pki.example.dto;

public class JwtResponse {
    private String token;
    private int expiresIn;
    private String jti;

    public JwtResponse(String token, int expiresIn,String jti) {
        this.token = token;
        this.expiresIn = expiresIn;
        this.jti = jti;
    }

    public String getToken() {
        return token;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public String getJti() {
        return jti;
    }

}
