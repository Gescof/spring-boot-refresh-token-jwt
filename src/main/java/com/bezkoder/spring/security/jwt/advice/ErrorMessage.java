package com.bezkoder.spring.security.jwt.advice;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Date;

@Getter
@RequiredArgsConstructor
public class ErrorMessage {
    private final int statusCode;
    private final Date timestamp;
    private final String message;
    private final String description;
}
