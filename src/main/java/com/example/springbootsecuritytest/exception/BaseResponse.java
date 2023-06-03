package com.example.springbootsecuritytest.exception;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.sql.Timestamp;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BaseResponse {

    private int statusCode;
    private String exceptionType;
    private String message;
    private Timestamp timestamp;
}
