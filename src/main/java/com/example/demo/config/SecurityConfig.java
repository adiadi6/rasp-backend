package com.example.demo.config;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.beans.Customizer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    private final JwtAuthConverter jwtAuthConverter;
    private final JwtDecoder jwtDecoder;
    private final JwtCookieFilter jwtCookieFilter;

    public SecurityConfig(JwtAuthConverter jwtAuthConverter, JwtDecoder jwtDecoder, JwtCookieFilter jwtCookieFilter) {
        this.jwtAuthConverter = jwtAuthConverter;
        this.jwtDecoder = jwtDecoder;
        this.jwtCookieFilter = jwtCookieFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsFilter()))
                .csrf(csrf -> csrf.disable())
//                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/login", "/api/auth/callback", "/api/auth/logout").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(new KeycloakTokenFilter(),
                        BearerTokenAuthenticationFilter.class) // Add custom introspection filter
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter)));

        return http.build();
    }

    @Bean
        public CorsConfigurationSource corsFilter() {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowCredentials(true); // Allow credentials (cookies)
            config.setAllowedOrigins(Arrays.asList("http://localhost:5173")); // Explicitly allow frontend
            config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
            config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With", "Accept"));
            config.setExposedHeaders(Arrays.asList("Authorization", "Set-Cookie")); // Ensure cookies are exposed

            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", config);
            return source;
        }
}
