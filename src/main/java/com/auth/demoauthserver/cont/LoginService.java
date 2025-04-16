package com.auth.demoauthserver.cont;

import com.auth.demoauthserver.CustomROPCTokenGenerator;
import com.auth.demoauthserver.ROPCAuthenticationToken;
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
  private CustomROPCTokenGenerator customROPCTokenGenerator;

  @PostMapping("/custom-token")
  public ResponseEntity<OAuth2AccessTokenResponse> getToken() {
    
    // antes de continuar validamos las credenciales (de la misma manera que se está hoy haciendo en las apps,
    // ya sea consultando en BD o consumiendo un servicio a SVN de verificación de credenciales)

    // Creamos el principal y luego generamos y guardamos el token (jwt oauth compliant) de autenticación
    User user = new User("EXNOdjaramib", "", List.of(new SimpleGrantedAuthority("ROLE_USER")));
    OAuth2AccessTokenResponse tokenResponse = customROPCTokenGenerator.generarToken(user, "oidc-client");

    return ResponseEntity.ok(tokenResponse);
  }
}
