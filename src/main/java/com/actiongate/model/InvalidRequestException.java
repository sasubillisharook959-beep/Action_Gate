package com.actiongate.model;

public class InvalidRequestException extends IllegalArgumentException {
    public InvalidRequestException(String message) {
        super(message);
    }
}
