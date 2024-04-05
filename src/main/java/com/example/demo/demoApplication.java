package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.HashMap;
import java.util.Map;

@Controller
@SpringBootApplication
public class demoApplication {

    @Autowired
    private OAuth2AuthorizedClientService clientService;

    @Autowired
    private Environment environment;

    @GetMapping("/home")
    public String home(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userName = authentication.getName();

        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            OAuth2AuthorizedClient authorizedClient = clientService.loadAuthorizedClient(
                    oauthToken.getAuthorizedClientRegistrationId(), oauthToken.getName()
            );

            if (authorizedClient != null) {
                OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
                OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();

                String accessTokenValue = accessToken != null ? accessToken.getTokenValue() : "not available";
                String refreshTokenValue = refreshToken != null ? refreshToken.getTokenValue() : "not available";

                model.addAttribute("userName", userName);
                model.addAttribute("accessToken", accessTokenValue);
                model.addAttribute("refreshToken", refreshTokenValue);

                OAuth2User oauth2User = (OAuth2User) oauthToken.getPrincipal();
                Map<String, Object> userAttributes = oauth2User.getAttributes();
                model.addAttribute("userAttributes", userAttributes);

                String registrationId = oauthToken.getAuthorizedClientRegistrationId();
                String clientId = environment.getProperty("spring.security.oauth2.client.registration." + registrationId + ".client-id");
                String provider = environment.getProperty("spring.security.oauth2.client.registration." + registrationId + ".provider");
                String redirectUri = environment.getProperty("spring.security.oauth2.client.registration." + registrationId + ".redirect-uri");
                String governmentCode = environment.getProperty("spring.security.oauth2.client.registration." + registrationId + ".goverment-code");
                String authorizationUri = environment.getProperty("spring.security.oauth2.client.provider." + registrationId + ".authorization-uri");
                String tokenUri = environment.getProperty("spring.security.oauth2.client.provider." + registrationId + ".token-uri");
                String revocationEndpoint = environment.getProperty("spring.security.oauth2.client.provider." + registrationId + ".revocation_endpoint");
                String introspectionEndpoint = environment.getProperty(
                        "spring.security.oauth2.client.provider." + registrationId + ".introspection_endpoint");
                
                // Scopeを取得してmodelに追加
                String scope = authorizedClient.getAccessToken().getScopes().toString();

                model.addAttribute("scope", scope);

                model.addAttribute("clientId", clientId);
                model.addAttribute("provider", provider);
                model.addAttribute("redirectUri", redirectUri);
                model.addAttribute("governmentCode", governmentCode);
                model.addAttribute("authorizationUri", authorizationUri);
                model.addAttribute("tokenUri", tokenUri);
                model.addAttribute("revocationEndpoint", revocationEndpoint);
                model.addAttribute("introspectionEndpoint", introspectionEndpoint);

                String realm = environment.getProperty("spring.security.oauth2.client.provider." + registrationId + ".issuer", "not available");
                model.addAttribute("realm", realm);

                if (authentication.getPrincipal() instanceof OidcUser) {
                    OidcIdToken idToken = ((OidcUser) authentication.getPrincipal()).getIdToken();
                    if (idToken != null) {
                        String idTokenValue = idToken.getTokenValue();
                        model.addAttribute("IDToken", idTokenValue);
                    } else {
                        String idTokenValue = "none";
                        model.addAttribute("IDToken", idTokenValue);
                    }
                } else {
                    String idTokenValue = "not oidcuser";
                    model.addAttribute("IDToken", idTokenValue);
                }

                return "home";
            }
        }

        return "home";
    }

    public static void main(String[] args) {
        SpringApplication.run(demoApplication.class, args);
    }
}
