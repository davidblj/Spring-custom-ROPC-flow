package com.auth.demoauthserver.cont;

import com.auth.demoauthserver.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/info")
public class ControllerInfo {

    @Autowired
    private OAuth2AuthorizationService authorizationService;
    
    @Autowired
    /**
     * Servicio de prueba
     *
     * @return
     */
    @GetMapping
    public String getInfo() {
        System.out.println("OK!");
        return "info";
    }

    /**
     * Cierre de session
     *
     * @param token
     * @return
     */
    @PostMapping("/logout")
    public String logout(@RequestParam("token") String token) {
        
        OAuth2Authorization authorization = authorizationService.findByToken(token, null);
        if (authorization != null) {
            authorizationService.remove(authorization);
            return "Logged out successfully!";
        } else {
            return "Invalid token!";
        }
    }
}
