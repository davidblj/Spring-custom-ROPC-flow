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
    
    // antes de continuar validamos las credenciales (de la misma manera que se esta hoy aciendo en las app,
    // ya sea consultando en BD o consumiendo un servicio a SVN)

    // Creamos el principal y luego generamos y guardamos el token (jwt oauth complient) de autenticación
    User user = new User("EXNOdjaramib", "", List.of(new SimpleGrantedAuthority("ROLE_USER")));
    OAuth2AccessTokenResponse tokenResponse = tokenService.generateToken(user, "oidc-client");

    return ResponseEntity.ok(tokenResponse);
  }
}
