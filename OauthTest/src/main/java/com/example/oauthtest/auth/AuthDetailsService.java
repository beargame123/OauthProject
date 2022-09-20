package com.example.oauthtest.auth;

import com.example.oauthtest.entity.User;
import com.example.oauthtest.oauth.OAuth2Attribute;
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

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class AuthDetailsService implements UserDetailsService, OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    //<OAuth2UserRequest, OAuth2User> 제네릭 문법으로 인자로 들어올 정확한 타입을 모르기 때문에 쓰임

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return  userRepository.findByEmail(email)
                .map(AuthDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("NOT_FOUND_USER"));
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();

        // UserInfo에서 사용자의 attributes를 가져온 후 OAuth2User를 통해 반환
        OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);

        // 현재 로그인 진행중인 서비스를 구분하는 코드 구글, 페북, 네이버 등
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        /* OAuth를 지원하는 Service에서 사용자를 구분하기 위한 유니크 필드가 서로 다르기 떄문에
           각 계정마다 유니크한 id값을 전달받기 위한 코드
           예를 들어 구글은 sub라는 필드가 유니크 키이고 네이버는 id라는 필드가 유니크키이다.
         */
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        // OAuth2UserService를 통해 가져온 oAuth2User의 attribute를 담는 클래스
        OAuth2Attribute oAuth2Attribute = OAuth2Attribute
                .of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        // user에 값이 있다면 update, 값이 없다면 save를 한다.
        User user = saveOrUpdate(oAuth2Attribute);

        // 로그인한 유저를 리턴함
        return new DefaultOAuth2User(
                Collections.singleton(
                        new SimpleGrantedAuthority(user.getRoleKey())),

                oAuth2Attribute.getAttributes(),
                oAuth2Attribute.getAttributeKey()
        );

    }

    //User 저장하고 이미 있는 데이터면 Update
    private User saveOrUpdate(OAuth2Attribute attribute) {
        User user = userRepository.findByEmail(attribute.getEmail())
                .map(entity ->entity.update(attribute.getName(), attribute.getPicture()))
                .orElse(attribute.toEntity());
        return userRepository.save(user);
    }

}
