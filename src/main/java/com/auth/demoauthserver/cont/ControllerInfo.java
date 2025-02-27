package com.auth.demoauthserver.cont;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/info")
public class ControllerInfo {



    @GetMapping
    public String getInfo() {
        System.out.println("NO EJECUTAR!");
        return "info";
    }

    @Autowired
    private OAuth2AuthorizationService authorizationService;

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
