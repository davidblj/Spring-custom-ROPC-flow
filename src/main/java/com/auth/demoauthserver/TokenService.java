package com.auth.demoauthserver;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Set;

@Service
public class TokenService {

  private final RegisteredClientRepository registeredClientRepository;
  private final OAuth2AuthorizationService authorizationService;
  private final OAuth2TokenGenerator<?> tokenGenerator;

  public TokenService(RegisteredClientRepository registeredClientRepository,
                            OAuth2AuthorizationService authorizationService,
                            OAuth2TokenGenerator<?> tokenGenerator) {
    this.registeredClientRepository = registeredClientRepository;
    this.authorizationService = authorizationService;
    this.tokenGenerator = tokenGenerator;
  }

  public OAuth2AccessTokenResponse generateToken(User userPrincipal, String clientId) {
    RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

    Authentication principal = new UsernamePasswordAuthenticationToken(
        userPrincipal.getUsername(), null, userPrincipal.getAuthorities());
    AuthorizationGrantType grantType = new AuthorizationGrantType("custom_password");

    OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
        .registeredClient(registeredClient)
        .principal(principal)
        .authorizedScopes(Set.of("openid", "profile"))
        .tokenType(OAuth2TokenType.ACCESS_TOKEN)
        .authorizationGrantType(grantType)
        .authorizationGrant(principal) // You could pass a custom grant here
        .build();

//    OAuth2AccessToken accessToken = (OAuth2AccessToken) tokenGenerator.generate(context);
    OAuth2Token token = tokenGenerator.generate(context);
    OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token.getTokenValue(), token.getIssuedAt(), token.getExpiresAt(), Set.of("openid", "profile"));
    
    OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
        .principalName(userPrincipal.getUsername())
        .authorizationGrantType(grantType)
        .token(accessToken)
        .build();

    authorizationService.save(authorization);

    return OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
        .tokenType(accessToken.getTokenType())
        .scopes(accessToken.getScopes())
        .expiresIn(accessToken.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond())
        .build();
  }
}
