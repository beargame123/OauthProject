package com.example.oauthtest.auth;

import com.example.oauthtest.entity.User;
import com.example.oauthtest.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.util.Collections;

@Service
@RequiredArgsConstructor
public class AuthDetailsService implements UserDetailsService{
    //<OAuth2UserRequest, OAuth2User> 제네릭 문법으로 인자로 들어올 정확한 타입을 모르기 때문에 쓰임

    private final UserRepository userRepository;
    private final HttpSession httpSession;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return  userRepository.findByEmail(email)
                .map(AuthDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("NOT_FOUND_USER"));
    }
}
