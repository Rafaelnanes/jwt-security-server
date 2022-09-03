package com.jwt.security.server.config;

import com.jwt.security.server.security.filter.JwtTokenFilter;
import com.jwt.security.server.service.TokenService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

@Configuration
public class ApplicationConfig {

  @Bean
  public JwtTokenFilter getJwtFilter(UserDetailsService userDetailsService, TokenService tokenService) {
    return new JwtTokenFilter(userDetailsService, tokenService);
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
  public TokenService getTokenGenerator() {
    return new TokenService();
  }

}
