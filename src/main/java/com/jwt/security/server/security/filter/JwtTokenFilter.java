package com.jwt.security.server.security.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.jwt.security.server.service.TokenService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@AllArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

  private final UserDetailsService userDetailsService;

  private final TokenService tokenService;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (StringUtils.hasText(authorization) && authorization.startsWith("Bearer ")) {
      String token = authorization.split(" ")[1];
      DecodedJWT jwt = tokenService.verify(token);
      String subject = jwt.getSubject();
      UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
      SecurityContextHolder.getContext().setAuthentication(
          new UsernamePasswordAuthenticationToken(userDetails.getUsername(), userDetails.getPassword(),
              userDetails.getAuthorities()));

    }
    filterChain.doFilter(request, response);
  }
}
