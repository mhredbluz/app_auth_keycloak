package br.com.marcos.app_auth_keycloak.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity //Habilita os @PreAuthorized methods da nossa aplicação
public class SecurityConfig {
    
    /*A gente pode tanto utilizar o keycloak por fora pra fazer a auth ou utilizar a apllicação 
     * Vamos Gerar o token pela aplicação
     * Toda vez que configuramos o Spring Security dentro da aplicação, todas as rotas precisam passar pela segurança, caso contrário 
     * ele bloqueia todas as rotas desconhecidas
    */

    @Bean
    public SecurityFilterChain SecurityFilterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf -> csrf.disable())
            .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt.jwtAuthenticationConverter(new JWTConverter())));

        return http.build();
    }
}
