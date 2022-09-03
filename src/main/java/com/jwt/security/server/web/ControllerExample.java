package com.jwt.security.server.web;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.jwt.security.server.model.TokenResponse;
import com.jwt.security.server.service.TokenService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/root")
@AllArgsConstructor
public class ControllerExample {

  private final TokenService tokenService;

  @GetMapping("/hello")
  public String getExample() {
    return "Hello";
  }

  @GetMapping("/token")
  public TokenResponse getToken() {
    UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    String token = tokenService.generateToken(userDetails.getUsername());
    return TokenResponse.builder()
                        .accessToken(token)
                        .build();
  }

  @GetMapping("/introspection")
  public DecodedJWT getToken(HttpServletRequest request) {
    String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
    return tokenService.verify(authorization.split(" ")[1]);
  }

}
