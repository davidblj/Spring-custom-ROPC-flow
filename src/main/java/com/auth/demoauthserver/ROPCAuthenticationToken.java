package com.auth.demoauthserver;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class ROPCAuthenticationToken extends UsernamePasswordAuthenticationToken {
  
  private String jsonUser;

  public ROPCAuthenticationToken(Object principal, Object credentials) {
    super(principal, credentials);
  }

  public ROPCAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities, String jsonUser) {
    super(principal, credentials, authorities);
    this.jsonUser = jsonUser;
  }

  public String getJsonUser() {
    return jsonUser;
  }
}
