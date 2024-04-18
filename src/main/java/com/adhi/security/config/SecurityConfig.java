package com.adhi.security.config;


import io.jsonwebtoken.Jwt;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;


/**
 * {@link Configuration} and {@link EnableWebSecurity} must be used together to make it work in Spring Boot 3+
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFitler;
    private final AuthenticationProvider authenticationProvider;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthFitler,
                          AuthenticationProvider authenticationProvider) {
        this.jwtAuthFitler = jwtAuthFitler;
        this.authenticationProvider = authenticationProvider;
    }


    /** Spring Security will look for {@link org.springframework.security.web.SecurityFilterChain}
     * {@link org.springframework.security.web.SecurityFilterChain} bean is responsible for configuring all HTTP security of the application
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
//                .csrf().disable()
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
                        .requestMatchers("/auth/**").permitAll() // patterns mentioned are permitted without authentication
                        .anyRequest().authenticated()) // other than mentioned patterns, every other request should be authenticated
                /** {@link OncePerRequestFilter} was used to authenticate every incoming request
                 * The session should be stateless, i.e,. Will not store (Authentication or Session) state, each req. should be authenticated
                 * */
                .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                /** Should specify which {@link AuthenticationProvider} to use. We must specify {@link Jwt} */
                .authenticationProvider(authenticationProvider)
                /** Executing this filter before {@link UsernamePasswordAuthenticationFilter} */
                .addFilterBefore(jwtAuthFitler, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }

}
