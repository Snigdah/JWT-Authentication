package com.example.security.service.impl;

import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class LogoutService {
    private Set<String> blacklist = new HashSet<>();

    public boolean isTokenBlacklisted(String token) {
        return blacklist.contains(token);
    }

    public void blacklistToken(String token) {
        blacklist.add(token);
    }
    public boolean logout(String token) {
        if (token != null && !isTokenBlacklisted(token)) {
            blacklistToken(token);
            return true;
        }
        return false;
    }
}
