package com.security.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;
import java.util.Collections;

@Configuration
@EnableWebSecurity(debug = true)
public class WebSecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtFilter jwtFilter) throws Exception {
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

        .and()
        .addFilterBefore(jwtFilter, AnonymousAuthenticationFilter.class);

    return http.build();
  }


  @Bean
  public JwtFilter getJwtFilter(UserDetailsService userDetailsService) {
    return new JwtFilter(userDetailsService);
  }

  @Bean
  public DaoAuthenticationProvider authProvider(UserDetailsService userDetailsService, PasswordEncoder encoder) {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService);
    authProvider.setPasswordEncoder(encoder);
    return authProvider;
  }

  @Bean
  public UserDetailsService getUserDetailsService(PasswordEncoder encoder) {
    return username -> {
      if ("myUser".equalsIgnoreCase(username)) {
        return new User(username, encoder.encode("myPassword"),
            Collections.singletonList((GrantedAuthority) () -> "SIMPLE_USER"));
      }
      return null;
    };
  }

  @Bean
  public PasswordEncoder encoder() {
    return new BCryptPasswordEncoder();
  }

}