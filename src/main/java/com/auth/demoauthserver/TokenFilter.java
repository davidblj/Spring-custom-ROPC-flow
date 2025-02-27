package com.auth.demoauthserver;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class TokenFilter extends OncePerRequestFilter {

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = request.getHeader("Authorization");
            if (jwt != null) {
                jwt = jwt.replace("Bearer ", "");
                OAuth2Authorization authorization = authorizationService.findByToken(jwt, OAuth2TokenType.ACCESS_TOKEN);
                if (authorization == null) {
                    throw new AccessDeniedException("No tiene permisos para acceder al recurso");
                }
            }
        } catch (AccessDeniedException e) {
            System.out.println(e.getMessage());
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return;
        } catch (Exception e) {
            //TODO
        }
        filterChain.doFilter(request, response);
    }

}
