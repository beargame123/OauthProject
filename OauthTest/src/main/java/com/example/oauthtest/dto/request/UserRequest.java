package com.example.oauthtest.dto.request;

import lombok.*;

@RequiredArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class UserRequest {
    public String email;
    public String password;
    public String introduce;

    @Builder
    public UserRequest(String email, String introduce){
        this.email = email;
        this.introduce = introduce;
    }
}
