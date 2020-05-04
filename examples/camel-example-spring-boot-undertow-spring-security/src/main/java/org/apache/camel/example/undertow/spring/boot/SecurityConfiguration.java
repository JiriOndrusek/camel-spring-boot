package org.apache.camel.example.undertow.spring.boot;

import org.apache.camel.component.spring.security.keycloak.KeycloakJwtAuthenticationConverter;
import org.apache.camel.component.spring.security.keycloak.KeycloakUsernameSubClaimAdapter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.Collections;

@Configuration
public class SecurityConfiguration {

    @EnableWebSecurity
    public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        public void init(WebSecurity web) throws Exception {
            super.init(web);
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .oauth2ResourceServer()
                    .jwt()
                    .jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter());
        }
    }


    @Bean
    public JwtDecoder jwtDecoderByIssuerUri(ClientRegistrationRepository repository) {
        final String jwkSetUri = repository.findByRegistrationId("keycloak").getProviderDetails().getJwkSetUri();
        final NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        // Use preferred_username from claims as authentication name, instead of UUID subject
        jwtDecoder.setClaimSetConverter(new KeycloakUsernameSubClaimAdapter("preferred_username"));
        return jwtDecoder;
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(Collections.singletonList(getKeycloakRegistration()));
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {

        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }

    private ClientRegistration getKeycloakRegistration() {
        return ClientRegistration.withRegistrationId("keycloak")
                .clientId("example-app")
                .clientSecret("bd2b0fe9-d08d-4a60-b5be-c65f6ec30290")
                .clientName("example-service")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid","profile", "email")
                .authorizationUri("http://localhost:8080/auth/realms/example-app/protocol/openid-connect/auth")
                .tokenUri("http://localhost:8080/auth/realms/example-app/protocol/openid-connect/token")
                .userInfoUri("http://localhost:8080/auth/realms/example-app/protocol/openid-connect/userinfo")
                .jwkSetUri("http://localhost:8080/auth/realms/example-app/protocol/openid-connect/certs")
                .userNameAttributeName("preferred_username")
                .build();
    }

}