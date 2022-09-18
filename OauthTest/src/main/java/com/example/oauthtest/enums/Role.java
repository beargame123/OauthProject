package com.example.oauthtest.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
    USER("ROLE_USER", "유저"),
    ADMIN("ROLE_ADMIN", "어드민");

    private final String key;
    private final String title;

}
