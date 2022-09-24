package com.example.oauthtest.jwt;

import com.example.oauthtest.dto.request.TokenDto;
import com.example.oauthtest.enums.Role;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;

@RequiredArgsConstructor
@Component
@Slf4j
public class JwtTokenProvider {
    private String secretKey = "jwtTest";

    // AccessToken 유효시간 1시간
    private final Long accessTokenValidMillisecond = 60 * 60* 1000L; // 1000L 은 1초이다.

    // RefreshToken 유효시간 1주일
    private final Long refreshTokenValidMillisecond = 7 *24 * 60 * 60 * 1000L;

    private final UserDetailsService userDetailsService;

    @PostConstruct // 의존하는 객체를 초기화해줌, secretKey를 Base64로 인코딩함
    protected void init(){
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // JWT 토큰 생성
    public TokenDto createToken(String userPK, Role roles){
        Claims claims = Jwts.claims().setSubject(userPK); // Jwt payload 에 저장되는 정보 단위
        claims.put("roles", roles); // key/value 쌍으로 저장
        Date now = new Date();

        // AccessToken
        String accessToken =Jwts.builder()
                .setClaims(claims) // 정보 저장
                .setIssuedAt(now)  // 발행시간
                .setExpiration(new Date(now.getTime() + accessTokenValidMillisecond)) // 만료시간
                .signWith(SignatureAlgorithm.HS256, secretKey) // 암호화
                .compact();

        // RefreshToken
        String refreshToken = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + refreshTokenValidMillisecond))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();

        return TokenDto.builder()
                .grantType("bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessTokenExpireDate(accessTokenValidMillisecond)
                .build();
    }

    // Jwt 토큰 인증 정보 조회
    public Authentication getAuthentication(String token){

        // Jwt 에서 claims 추출
        Claims claims = parseClaims(token);

        // 권한 정보가 없음
        if(claims.get("roles") == null){
            log.error("권한이 없습니다.");
        }
        UserDetails userDetails = userDetailsService.loadUserByUsername(claims.getSubject());
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    // Jwt 토큰 복호화해서 가져오기
    public Claims parseClaims(String token){
        try {
            return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
        }catch (ExpiredJwtException e){
            return e.getClaims();
        }
    }

    // Request의 Header 에서 token값을 가져온다. "ACCESS_TOKEN" :"TOKEN값"
    public String resolveToken(HttpServletRequest request){return request.getHeader("ACCESS_TOKEN");}

    // 토큰의 유효성 + 만료일자 확인
    public boolean validateToken(String jwtToken){
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken);
            return true;
        }catch (JwtException | IllegalArgumentException e){
            log.error(e.toString());
            return false;
        }
    }
}
