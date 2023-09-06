package com.example.security.service.impl;

import com.example.security.DTO.AuthenticationRequest;
import com.example.security.DTO.AuthenticationResponseDTO;
import com.example.security.DTO.RegisterRequest;
import com.example.security.config.JwtService;
import com.example.security.exception.ResourceNotFoundException;
import com.example.security.service.IAuthenticationService;
import com.example.security.user.Role;
import com.example.security.user.User;
import com.example.security.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthenticationService implements IAuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;


    public AuthenticationResponseDTO register(RegisterRequest request) {
        // Check if the email already exists in the database
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new ResourceNotFoundException("Email address is already taken.");
        }
        // Create a new user entity
        String userID = JwtService.generateUserID(10);
        var user = User.builder()
                .userId(userID)
                .firstName(request.getFirstname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        // Save the user to the database
        userRepository.save(user);

        // Generate JWT token and return the response
        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponseDTO.builder()
                .userId(userID)
                .email(user.getEmail())
                .firstname(user.getFirstName())
                .lastname(user.getLastName())
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponseDTO authenticate(AuthenticationRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            var user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new ResourceNotFoundException("User not found"));

            var jwtToken = jwtService.generateToken(user);
            return AuthenticationResponseDTO.builder()
                    .userId(user.getUserId())
                    .email(user.getEmail())
                    .firstname(user.getFirstName())
                    .lastname(user.getLastName())
                    .token(jwtToken)
                    .build();
        } catch (Exception e) {
            // You can handle other exceptions here if needed
            throw new ResourceNotFoundException("Authentication failed");
        }
    }

    public String extractTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

}
