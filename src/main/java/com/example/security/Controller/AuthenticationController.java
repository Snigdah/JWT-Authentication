package com.example.security.Controller;

import com.example.security.DTO.AuthenticationRequest;
import com.example.security.DTO.AuthenticationResponseDTO;
import com.example.security.DTO.RegisterRequest;
import com.example.security.response.ResponseHandler;
import com.example.security.service.IAuthenticationService;
import com.example.security.service.impl.AuthenticationService;
import com.example.security.service.impl.LogoutService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final IAuthenticationService authenticationService;
    private final LogoutService logoutService;

    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody RegisterRequest request){
//        return ResponseEntity.ok(authenticationService.register(request));
        AuthenticationResponseDTO responseDTO = authenticationService.register(request);
        return ResponseHandler.generateResponse("Account Create SuccessFully", HttpStatus.CREATED,responseDTO);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponseDTO> authenticate(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        String token = authenticationService.extractTokenFromRequest(request);
        if (logoutService.logout(token)) {
            return ResponseEntity.ok("Logout successful");
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Logout failed");
    }
}
