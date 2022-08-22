package com.example.learningspringsecurity.sec;

public class JWTUtil {
    public static final String SECRET = "mySecretKey";
    public static final String AUT_HEADER = "Authorization";
    public static final String PREFIX = "Bearer ";
    public static final long EXPIRE_ACCESS_TOKEN = 1 * 60 * 1000;
    public static final long EXPIRE_REFRESH_TOKEN = 10 * 60 * 1000;
}
