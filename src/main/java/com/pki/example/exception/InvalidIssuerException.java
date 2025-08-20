package com.pki.example.exception;

public class InvalidIssuerException extends RuntimeException{
    public InvalidIssuerException(String message) {
        super(message);
    }
}
