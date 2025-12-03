package com.example.asiceverifier;

public class VerificationException extends RuntimeException {
    private final Errors code;

    public VerificationException(Errors code, String message) {
        super(message);
        this.code = code;
    }

    public Errors code() {
        return code;
    }
}
