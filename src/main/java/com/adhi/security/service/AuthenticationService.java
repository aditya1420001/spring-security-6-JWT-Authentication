package com.adhi.security.service;

import com.adhi.security.bean.request.AuthenticationRequest;
import com.adhi.security.bean.request.RegisterRequest;
import com.adhi.security.bean.response.AuthenticationResponse;
import com.adhi.security.config.JwtService;
import com.adhi.security.repository.UserRepository;
import com.adhi.security.user.Role;
import com.adhi.security.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;


    public AuthenticationResponse register(RegisterRequest request) {

        User user = User.builder()
                .email(request.getEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);

        // generating the token
        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        /** Throws exception when the username and password goes wrong */
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        User user = userRepository.findByEmail(request.getEmail()).orElseThrow();

        return AuthenticationResponse.builder()
                .token(jwtService.generateToken(user))
                .build();

    }
}
