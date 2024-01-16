package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인에 등록됨
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig{

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Bean //리턴되는 오브젝트를 IoC로 등록해줌
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable); //csrf 비활성화
        http.authorizeHttpRequests(authorize ->
                authorize
                        .requestMatchers("/user/**").authenticated() //user 경로는 인증이 필요함
                        .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER") //manager 경로는 인증 + ADMIN 혹은 MANAGER 권한이 필요함
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN") //admin 경로는 인증 + ADMIN 권한이 필요함
                        .anyRequest().permitAll() //다른 요청은 전부 허용
        );
        http.formLogin(auth -> auth.loginPage("/loginForm") // loginForm 경로에서 로그인
                .loginProcessingUrl("/login") //login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인 해줌 (컨트롤러에서 /login 만들지 않아도 됨)
                .defaultSuccessUrl("/")); // loginForm으로 직접 들어와서 로그인 성공하면 메인페이지로 이동, 로그인 페이지로 redirect된 경우에 로그인 성공하면 그 전 페이지로 이동
        http.oauth2Login(oauth -> oauth.loginPage("/loginForm") //소셜 로그인 완료 후처리가 필요함
                .userInfoEndpoint(userInfo -> userInfo.userService(principalOauth2UserService)));
        return http.build();
    }
    
}