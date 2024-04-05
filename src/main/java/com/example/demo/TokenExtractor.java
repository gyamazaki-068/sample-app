package com.example.demo;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class TokenExtractor {

    public Map<String, Object> extractTokenInfo(Authentication authentication) {
        Map<String, Object> tokenInfo = new HashMap<>();
        if (authentication != null && authentication.isAuthenticated()) {
            OAuth2AuthenticatedPrincipal principal = (OAuth2AuthenticatedPrincipal) authentication.getPrincipal();
            OAuth2AccessToken accessToken = principal.getAttribute("access_token");
            tokenInfo.put("access_token", accessToken.getTokenValue());
            
            // ユーザー属性情報の取得
            Map<String, Object> userAttributes = principal.getAttributes();
            if (userAttributes != null) {
                tokenInfo.putAll(userAttributes);
            }
        }
        return tokenInfo;
    }
}
