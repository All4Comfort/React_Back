package com.example.demo.security;

//이 클래스는 사용자의 정보를 받아서 JWT 토큰을 생성하는 역할을 합니다.
//나중에 이 토큰을 컨트롤러에 응답 시 같이 보내게 됩니다.
//정의하는 방법은 형식화되어 있으니 외우지 말고, 분석도 필요없고 개념만 잡으세요. 일반적으로 가져다 씁니다.

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.springframework.stereotype.Service;

import com.example.demo.model.UserEntity;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;



@Slf4j
@Service
public class TokenProvider {
  //제일 먼저 사용자의 PK와 조홥될 서버의 SecretKey를 선언합니다. 아무거나 선언해도 됩니다. 길게 하세요.

  private static final String SECRET_KEY = 
  "ASLDdsz4f56s47f68vf3s2d1rcad6654s6f4s354f354wefKJF4CF5D4A35S4Dvlsjfdlkjsldkfjs43543541e67643sd43s4dc4s3d4a35sd43554hf3g4h3df4hg35e4rg343ef43as4d4w3dw65ef3645g4df3g34f3s4dz4d35sf4s3d4f34s3d4fs4d3f4254V24HF544543fg54b3f54g3sz54vse5d4c6a5s4d6AWCxL545SDFOIJljlzfndvnzoleidsadawdwsdfvsSDKLK8932scdlsdasdASASDASDADzzcgs6d5rg4v6s6EV654AD3C4SD3F4AW34E3CD5A4DC476W8ERzzzzzzzz94j54x6ad7s1f3sdzg6s4vr6q7wed65acknflfcw3a3s4rt687ervgtzzzzzzzwqedw4d654s65v3df46g87a98vs7e98r6s8r76v5sfc4a3s1c3s22d1fv5sfv54e6d4rf";

  //컨트롤러에서 서비스로 등록해 사용자 정보를 담고 있는 Entity를 전달해서
  //암호화된 토큰을 생성하는 메서드를 정의
  public String create(UserEntity userEntity) {
    
    //토큰의 유효기간 설정부터 먼저 할게요.
    Date expireDate = Date.from(Instant.now().plus(10, ChronoUnit.DAYS));
    /*
     * Jwt.builder()를 이용해서 암호화된 토큰을 생성하는데, 결과는 아래처럼 구성됩니다.
     * {//header 부분
     *  "alg":"여러 알고리즘 중 하나"
     * }.
     * {
     *  //PayLoad부분
     *  "sub":"특정값...",
     *  "iss":"스프링부트 생성 시 group id",
     *  "iat":특정 숫자값,
     *  "exp":long 값
     * }.
     * 위 SECRET_KEY를 이용해서 서명한 값이 여기에 할당됨.(어떤 값이 나올지는 나중에 확인해보죠.)
     */
    return Jwts.builder()
            //header에 들어갈 내용 및 서명을 위한 비밀키
            .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
            //payload에 들어갈 내용 작성함
            .setSubject(userEntity.getId()) //user PK와 비밀키로 생성한 값
            .setIssuer("fullstack2")
            .setIssuedAt(expireDate)
            .compact();
  }

  //사용자로부터 전달받은 토큰을 64 Decoding해서
  //헤더, 페이로드로부터 전달받은 값들을 서버의 비밀키 이용하여 서명 후, 넘어온 토큰의 서명과 비교합니다.
  //만약 위조되지 않았다면 페이로드 (Claims 객체)를 리턴하고 아닌 경우엔 예외 날림.
  //이중 사용자의 id와 조합해서 token을 생성했으니 id값도 필요함
  public String validateAndGetUserId(String token){
    Claims claims = Jwts.parser()
              .setSigningKey(SECRET_KEY)
              .parseClaimsJws(token)
              .getBody();
    return claims.getSubject();
  }

}