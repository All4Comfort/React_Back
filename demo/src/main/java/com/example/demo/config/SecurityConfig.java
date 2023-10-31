package com.example.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.demo.security.JwtAuthenticationFilter;

import lombok.RequiredArgsConstructor;

//Spring Security의 구성 설정을 담고 있는 클래스
//Security 필터 config 설정 클래스
//특정 URL에 대해서 인증 없이 모두 접근 가능하도록 설정
//나중에 token 인증을 할 수 있도록 filter를 추가하는 작업도 할 예정

@Configuration // 이 클래스가 스프링 애플리케이션의 구성 설정 클래스임을 나타냄. Config 객체를 bean으로 등록.
@RequiredArgsConstructor // Lombok 프로젝트에서 제공하는 어노테이션으로, 필드 주입을 위한 생성자를 자동으로 생성
@EnableWebSecurity // 스프링 시큐리티 설정을 활성화
public class SecurityConfig {

  @Autowired
  private JwtAuthenticationFilter jwtAuthenticationFilter; // JWT (JSON Web Token) 기반의 인증을 처리

  // 아래 메서드는 SecurityFilterChain(스프링 시큐리티 필터 체인)을 구성하고 반환
  // WebToken secure filter를 리턴해서 스프링에 적용할 예정이기 때문.
  // 이때, 파라미터로 오는 객체를 이용해서 Secure 설정을 제어할 수도 있습니다.
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    // 기본 인증 해제
    http
        // HTTP 기본 인증을 비활성화. 즉, 사용자 이름과 암호를 사용한 HTTP 기본 인증을 사용하지 않도록 설정
        .httpBasic(httpBasicConfigurer -> httpBasicConfigurer.disable())
        // .csrf().disable()는 Cross-Site Request Forgery (CSRF) 공격을 방지하는 CSRF 보호를 비활성화
        .csrf(csrfConfigurer -> csrfConfigurer.disable()
        )
        // Cross-Origin Resource Sharing (CORS) 설정을 구성하는 부분으로, CORS를 허용
        .cors()
            //논리구조의 구분과 가독성을 위해 사용됨
            .and()
        // STATELESS로 설정되어 세션을 사용하지 않음
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        // 요청에 대한 인증 및 권한 부여 규칙을 설정(조건별로 요청 허용/제한 설정)
        .authorizeHttpRequests()
            // root(로컬)와 auth 하위의 모든 path는 인증 없이 접근 가능함
            .requestMatchers("/", "/auth/**").permitAll()
            // 모든 다른 요청에 대해서는 인증이 필요
            .anyRequest().authenticated()
            .and()
        // JWT 토큰을 usernamepassword 필터 전에 끼워 넣기
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .exceptionHandling();

    // 위의 설정을 반영한 HttpSecurity 객체를 반환하고, 이것이 SecurityFilterChain을 완성.
    // 이 필터 체인을 리턴함으로써 Spring Security에 대한 설정을 완료
    return http.build();
  }
}
