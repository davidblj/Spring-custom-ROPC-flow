package com.auth.demoauthserver;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Set;

@Service
public class CustomROPCTokenGenerator {

  private final RegisteredClientRepository registeredClientRepository;
  private final OAuth2AuthorizationService authorizationService;
  private final OAuth2TokenGenerator<?> tokenGenerator;

  public CustomROPCTokenGenerator(RegisteredClientRepository registeredClientRepository,
                                  OAuth2AuthorizationService authorizationService,
                                  OAuth2TokenGenerator<?> tokenGenerator) {
    this.registeredClientRepository = registeredClientRepository;
    this.authorizationService = authorizationService;
    this.tokenGenerator = tokenGenerator;
  }

  public OAuth2AccessTokenResponse generarToken(User userPrincipal, String clientId) {
    
    RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
    AuthorizationGrantType grantType = new AuthorizationGrantType("ROCP");

    OAuth2Token jwt = crearToken(registeredClient, userPrincipal, grantType);
    guardarToken(userPrincipal, registeredClient, grantType, jwt);

    return OAuth2AccessTokenResponse.withToken(jwt.getTokenValue())
        .tokenType(OAuth2AccessToken.TokenType.BEARER)
        .scopes(Set.of("openid", "profile"))
        .expiresIn(jwt.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond())
        .build();
  }

  private OAuth2Token crearToken(RegisteredClient registeredClient, User userPrincipal, AuthorizationGrantType grantType) {
    Authentication principal = new UsernamePasswordAuthenticationToken(userPrincipal.getUsername(), null, userPrincipal.getAuthorities());
    OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
        .registeredClient(registeredClient)
        .principal(principal)
        .authorizedScopes(Set.of("openid", "profile"))
        .tokenType(OAuth2TokenType.ACCESS_TOKEN)
        .authorizationGrantType(grantType)
        .authorizationGrant(principal)
        .build();
    OAuth2Token jwt = tokenGenerator.generate(context);
    if (!(jwt instanceof Jwt)) {
      throw new IllegalStateException("TokenGenerator did not return a JWT");
    }
    return jwt;
  }

  private void guardarToken(User userPrincipal, RegisteredClient registeredClient, AuthorizationGrantType grantType, OAuth2Token jwt) {
    // se enmascara el token en el tipo OAuth2AccessToken para que el servicio de autorización lo registre bajo esta clase
    // y luego permita ser encontrado usando 'authorizationService.findByToken(jwt, OAuth2TokenType.ACCESS_TOKEN)'
    OAuth2AccessToken accessToken = new OAuth2AccessToken(
        OAuth2AccessToken.TokenType.BEARER,
        jwt.getTokenValue(),
        jwt.getIssuedAt(),
        jwt.getExpiresAt(),
        Set.of("openid", "profile")
    );
    
    OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
        .principalName(userPrincipal.getUsername())
        .authorizationGrantType(grantType)
        .token(accessToken, metadata -> metadata.put(Jwt.class.getName(), jwt))
        .build();
    
    // se guarda el token en memoria en el servidor de autorización de Spring
    authorizationService.save(authorization);
  }
}
