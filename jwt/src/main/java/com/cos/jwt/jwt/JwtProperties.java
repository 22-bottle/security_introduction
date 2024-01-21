package com.cos.jwt.jwt;

public interface JwtProperties {

    String SECRET = "joblog";
    int EXPIRATION_TIME = 60000 * 10; //10분
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
