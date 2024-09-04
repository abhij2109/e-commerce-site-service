package com.abhi.ecom.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;
import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth->auth.requestMatchers("/api/**").authenticated().anyRequest().permitAll())
                .addFilterBefore(new JwtValidator(), BasicAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors->cors.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration cfg = new CorsConfiguration();
                        cfg.setAllowedOrigins(List.of(
                                "http://localhost:3000"
                        ));
                        cfg.setAllowedMethods(Collections.singletonList("*"));
                        cfg.setAllowCredentials(true);
                        cfg.setAllowedHeaders(Collections.singletonList("*"));
                        cfg.addExposedHeader(List.of("Authorization").toString());
                        return cfg;
                    }
                }))
                .formLogin(AbstractAuthenticationFilterConfigurer::permitAll)
                .logout(logout -> logout.logoutUrl("/logout"));

        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
