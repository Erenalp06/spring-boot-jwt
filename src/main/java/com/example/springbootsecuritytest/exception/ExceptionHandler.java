package com.example.springbootsecuritytest.exception;

import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.sql.Timestamp;

@ControllerAdvice
public class ExceptionHandler {

    @org.springframework.web.bind.annotation.ExceptionHandler(value = {ExpiredJwtException.class})
    public ResponseEntity<BaseResponse> handleNotFoundException(ExpiredJwtException ex, WebRequest request) {
        String errorMessage = "token expired";
        String exceptionType = ex.getClass().getSimpleName();
        BaseResponse baseResponse = BaseResponse.builder()
                .statusCode(HttpStatus.FORBIDDEN.value())
                .exceptionType(exceptionType)
                .message(errorMessage)
                .timestamp(new Timestamp(System.currentTimeMillis()))
                .build();
        return new ResponseEntity<>(baseResponse, HttpStatus.FORBIDDEN);
    }
}
