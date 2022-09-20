package com.example.oauthtest.dto.request;

import com.example.oauthtest.entity.User;
import lombok.Builder;
import lombok.Getter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

import java.io.Serializable;

@Getter
@Builder
public class SessionUser implements Serializable {
    private final String name;
    private final String email;
    private final String picture;

    public SessionUser(User user) {
        this.name = user.getName();
        this.email = user.getEmail();
        this.picture = user.getPicture();
    }

}

