package com.example.oauthtest.auth;

import com.example.oauthtest.entity.User;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
@Getter
public class AuthDetails implements UserDetails {

    private final User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(user.getRole().name()));
        return roles;
    }

    // 사용자의 id를 반환
    @Override
    public String getUsername() {
        return user.getEmail();
    }

    // 사용자의 pw를 반환
    @Override
    public String getPassword(){
        return user.getPassword();
    }

    // 계정 만료 여부 반환
    @Override
    public boolean isAccountNonExpired() {
        return true; //만료 안됨
    }

    // 계정 잠금 여부 반환
    @Override
    public boolean isAccountNonLocked() {
        return true; //잠금 안됨
    }

    // 패스워드의 만료 여부 반환
    @Override
    public boolean isCredentialsNonExpired() {
        return true; //만료 안됨
    }

    // 계정 사용 가능 여부 반환
    @Override
    public boolean isEnabled() {
        return true; //계정 사용 가능
    }
}

