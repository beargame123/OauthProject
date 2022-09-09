package com.example.oauthtest.filter;

import com.example.oauthtest.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends GenericFilterBean{
    private final JwtTokenProvider jwtTokenProvider;

    // request 로 들어가는 Jwt의 유효성 검증
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // request 에서 token 취함.
        String token = jwtTokenProvider.resolveToken((HttpServletRequest)request);

        // 검증
        log.info("토큰을 확인하는중");
        log.info(((HttpServletRequest) request).getRequestURI());

        if(token != null && jwtTokenProvider.validateToken(token)){
            // 토큰이 유효하면 토큰으로부터 유저 정보를 가져옴
            Authentication authentication = jwtTokenProvider.getAuthentication(token);
            // SpringContext 에 Authentication 객체를 가져옴
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request,response);
    }
}
