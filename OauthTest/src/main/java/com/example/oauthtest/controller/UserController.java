package com.example.oauthtest.controller;

import com.example.oauthtest.dto.request.TokenDto;
import com.example.oauthtest.dto.request.UserRequest;
import com.example.oauthtest.entity.User;
import com.example.oauthtest.enums.Role;
import com.example.oauthtest.jwt.JwtTokenProvider;
import com.example.oauthtest.repository.UserRepository;
import com.example.oauthtest.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/my")
    public UserRequest myPage(Authentication authentication){
        if(authentication == null){
            throw new BadCredentialsException("USER_INFO_NOT_FOUND");
        }
        return userService.myPage(authentication.getName());
    }

    @GetMapping("/user/page")
    public String userPage(){
        return "유저 페이지에 진입을 성공하였습니다!";
    }

    @GetMapping("/admin/page")
    public String adminPage(){
        return "유저 페이지에 진입을 성공하였습니다!";
    }

    @GetMapping("/all/page")
    public String allPage() {
        return "권한이 없는 페이지에 진입을 성공하였습니다!";
    }
}
