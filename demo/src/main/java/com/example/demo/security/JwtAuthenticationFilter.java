package com.example.demo.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest; //security를 처음 적용한 게 서블릿...그래서 지금도 servlet을 패키지를 가져다 씀
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component

public class JwtAuthenticationFilter extends OncePerRequestFilter{

  @Autowired
  private TokenProvider tokenProvider;

  private String parseBearerToken(HttpServletRequest request){
    //bearerToken : 토큰을 전송하면 브라우저에 토큰의 키 이름을 나타냅니다.
    //이 값이 있다면 토큰값만 분리해서 리턴함
    String bearerToken = request.getHeader("Authorization");

    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {

      System.out.println("파싱된 토큰 값 : " + bearerToken.substring(7));
      return bearerToken.substring(7);
    }
    return null;
  }
  
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
        try {
          String token = parseBearerToken(request);

          if (token != null && !token.equalsIgnoreCase("null")) {
            String userId = tokenProvider.validateAndGetUserId(token);

            System.err.println("인증 USER ID : " + userId);

            //인증이 완료됐으면, 인증을 담당하는 ContextHolder 에 등록을 해줘야만 부트 시큐어에서 인증된 사용자로 인식함

            //생성자의 첫번째 파라미터 principal : 해당 ID로 부여된 토큰을 filter가 검증할 수 있는 key
            //이 값은 주어진 변수 이름 그대로 컨트롤러에서 사용할 수 있다.
            //그 제공자로 @AuthenticationPrincipal 어노테이션을 써줘야 한다. 
            AbstractAuthenticationToken authenticationToken = 
                new UsernamePasswordAuthenticationToken(userId,null, AuthorityUtils.NO_AUTHORITIES);

            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(authenticationToken);
            SecurityContextHolder.setContext(securityContext);

          }

        } catch (Exception e) {
            logger.error("JWT 인증 필터에서 예외 발생함 :" + e.getMessage());
        }

        filterChain.doFilter(request, response);
  }
  
}
