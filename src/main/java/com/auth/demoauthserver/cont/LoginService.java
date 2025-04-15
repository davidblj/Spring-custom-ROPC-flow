package com.auth.demoauthserver.cont;

import com.auth.demoauthserver.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/login")
public class LoginService {

  @Autowired
  private TokenService tokenService;

  @PostMapping("/custom-token")
  public ResponseEntity<OAuth2AccessTokenResponse> getToken() {
    
    // Step 1: Validate credentials with legacy backend (call legacy service)

    User user = new User("EXNOdjaramib", "", List.of(new SimpleGrantedAuthority("ROLE_USER")));

    // Step 3: Use TokenGenerator to create tokens
    OAuth2AccessTokenResponse tokenResponse = tokenService.generateToken(user, "oidc-client");

    return ResponseEntity.ok(tokenResponse);
  }
}
