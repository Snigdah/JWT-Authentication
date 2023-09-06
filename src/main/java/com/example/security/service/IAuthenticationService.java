package com.example.security.service;

import com.example.security.DTO.AuthenticationRequest;
import com.example.security.DTO.AuthenticationResponseDTO;
import com.example.security.DTO.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;

public interface IAuthenticationService {
    AuthenticationResponseDTO register(RegisterRequest request);

    AuthenticationResponseDTO authenticate(AuthenticationRequest request);

    String extractTokenFromRequest(HttpServletRequest request);
}
