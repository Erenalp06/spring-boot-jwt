package com.example.springbootsecuritytest.config;

import com.example.springbootsecuritytest.token.TokenRepository;
import com.example.springbootsecuritytest.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;


    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        jwt = authHeader.substring(7);
        final String username = jwtService.extractUsername(jwt);
        var user = userRepository.findByEmail(username).orElseThrow(() -> new IllegalStateException("user not found"));
        var token = tokenRepository.findTokenByUserId(user.getId()).orElse(null);
        if(token != null){
            token.setRevoked(true);
            tokenRepository.save(token);
        }


    }
}
