package com.example.security.config;

import com.example.security.service.impl.LogoutService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final LogoutService tokenBlacklistService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    )
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        // todo extract the userEmail from JWT token;
        userEmail = jwtService.extractUsername(jwt);

        if (tokenBlacklistService.isTokenBlacklisted(jwt)) {
            // Token is blacklisted, throw a custom exception
            System.out.println("token not valid");
        }

        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null && !tokenBlacklistService.isTokenBlacklisted(jwt)){
            // Check UserDetails from Database
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            //  Check user and token valid dor not
            if(jwtService.isTokenValid(jwt, userDetails)){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                authToken.setDetails(
                       new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // Update Security CContext
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        // After this if condition must have call this
        filterChain.doFilter(request, response);
    }
}
