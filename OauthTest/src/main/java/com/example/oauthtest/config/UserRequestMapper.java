package com.example.oauthtest.config;

import com.example.oauthtest.dto.request.SessionUser;
import com.example.oauthtest.entity.User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Component
public class UserRequestMapper {
    public SessionUser toDto(OAuth2User oAuth2User) {
        var attributes = oAuth2User.getAttributes();
        return SessionUser.builder()
                .email((String)attributes.get("email"))
                .name((String)attributes.get("name"))
                .picture((String)attributes.get("picture"))
                .build();
    }
}
