package com.pki.example.dto;

public class LoginRequest {

    private String email;
    private String password;
    private String recaptchaToken;
    private Integer twoFactorCode;

    public LoginRequest() {}

    public LoginRequest(String email, String password, String recaptchaToken, Integer twoFactorCode) {
        this.email = email;
        this.password = password;
        this.recaptchaToken = recaptchaToken;
        this.twoFactorCode = twoFactorCode;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRecaptchaToken() {
        return recaptchaToken;
    }

    public void setRecaptchaToken(String recaptchaToken) {
        this.recaptchaToken = recaptchaToken;
    }
    public Integer getTwoFactorCode() { return twoFactorCode; }
    public void setTwoFactorCode(Integer twoFactorCode) { this.twoFactorCode = twoFactorCode; }
}
