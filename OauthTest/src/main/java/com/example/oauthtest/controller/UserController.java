package com.example.oauthtest.controller;

import com.example.oauthtest.dto.request.TokenDto;
import com.example.oauthtest.dto.request.UserRequest;
import com.example.oauthtest.entity.User;
import com.example.oauthtest.enums.Role;
import com.example.oauthtest.jwt.JwtTokenProvider;
import com.example.oauthtest.repository.UserRepository;
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
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/signup")
    public void signUp(@RequestBody UserRequest request){
        userRepository.save(User.builder()
                .email(request.email)
                .introduce(request.introduce)
                .password(passwordEncoder.encode(request.password))
                .role(Role.ROLE_USER)
                .build());
    }

    @GetMapping(value = "/logout")
    public String logoutPage(HttpServletRequest request, HttpServletResponse response){
        new SecurityContextLogoutHandler().logout(request, response, SecurityContextHolder.getContext().getAuthentication());
        return "redirect/logout";
    }

    @PostMapping("/login")
    public TokenDto login(@RequestBody UserRequest request){
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new IllegalArgumentException("YOUR_NOT_SIGNUP"));
        if(!passwordEncoder.matches(request.getPassword(), user.getPassword())){
            log.error("WRONG_PASSWORD");
        }
        return jwtTokenProvider.createToken(user.getEmail(), user.getRole());
    }

    @DeleteMapping("/leave/{id}")
    public void leaveUser(@PathVariable Long id){
        User user = userRepository.findById(id).orElseThrow(() -> new UsernameNotFoundException("USER_NOT_FOUND"));
        userRepository.delete(user);
    }

    @GetMapping("/my")
    public void myPage(Authentication authentication){
        if(authentication == null){
            throw new BadCredentialsException("USER_INFO_NOT_FOUND");
        }
        return user
    }
}
