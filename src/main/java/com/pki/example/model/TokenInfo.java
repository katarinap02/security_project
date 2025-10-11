package com.pki.example.model;

import java.time.LocalDateTime;

public class TokenInfo {
    private String jti; // jedinstveni ID tokena
    private String ipAddress;
    private String userAgent;
    private LocalDateTime lastActivity;
    private String email;
    private String sub;

    public TokenInfo(String jti, String email, String ipAddress, String userAgent, LocalDateTime lastActivity) {
        this.jti = jti;
        this.email = email;
        this.sub = email;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.lastActivity = lastActivity;
    }

    // getteri i setteri
    public String getJti() { return jti; }
    public void setJti(String jti) { this.jti = jti; }
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
    public LocalDateTime getLastActivity() { return lastActivity; }
    public void setLastActivity(LocalDateTime lastActivity) { this.lastActivity = lastActivity; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getSub() { return sub; }
    public void setSub(String sub) { this.sub = sub; }
}
