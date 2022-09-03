package com.jwt.security.server.security;

import com.jwt.security.server.security.filter.JwtTokenFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity(debug = true)
public class WebSecurityConfig {
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtTokenFilter jwtTokenFilter) throws Exception {
    http
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()

        .exceptionHandling()
        .authenticationEntryPoint(
            (request, response, ex) -> {
              response.sendError(
                  HttpServletResponse.SC_UNAUTHORIZED,
                  ex.getMessage()
              );
            }
        )

        // Forbid any unauthorized requests
        .and()
        .authorizeHttpRequests()
        .anyRequest()
        .authenticated()

        .and()
        .httpBasic()

        // register jwt filter
        .and()
        .addFilterBefore(jwtTokenFilter, AnonymousAuthenticationFilter.class);

    return http.build();
  }

  @Bean
  public PasswordEncoder encoder() {
    return new BCryptPasswordEncoder();
  }

}