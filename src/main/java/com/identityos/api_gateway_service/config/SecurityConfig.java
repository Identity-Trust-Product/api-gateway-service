package com.identityos.api_gateway_service.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import reactor.core.publisher.Mono;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.http.HttpMethod;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http) {

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers("/actuator/**").permitAll()
                        .pathMatchers("/api/v1/auth/organization/**").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/onboarding/organizations").permitAll()
                        .pathMatchers("/api/v1/organization/**").hasRole("ORGANISATION_ADMIN")
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(keycloakJwtAuthenticationConverter()))
                )
                .build();
    }

        @Bean
        public CorsWebFilter corsWebFilter() {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.addAllowedOrigin("http://localhost:3000");
                configuration.addAllowedOrigin("http://127.0.0.1:3000");
                configuration.addAllowedMethod("GET");
                configuration.addAllowedMethod("POST");
                configuration.addAllowedMethod("PUT");
                configuration.addAllowedMethod("DELETE");
                configuration.addAllowedMethod("OPTIONS");
                configuration.addAllowedHeader("*");
                configuration.setAllowCredentials(false);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return new CorsWebFilter(source);
        }

        private Converter<Jwt, Mono<? extends AbstractAuthenticationToken>> keycloakJwtAuthenticationConverter() {
                JwtGrantedAuthoritiesConverter scopeConverter = new JwtGrantedAuthoritiesConverter();
                return jwt -> {
                        var authorities = new java.util.ArrayList<>(scopeConverter.convert(jwt));
                        var roles = jwt.getClaimAsMap("realm_access");
                        if (roles != null && roles.get("roles") instanceof java.util.Collection<?> roleNames) {
                                roleNames.stream()
                                                .map(Object::toString)
                                                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                                                .forEach(authorities::add);
                        }
                        return Mono.just(new JwtAuthenticationToken(jwt, authorities));
                };
        }
}
