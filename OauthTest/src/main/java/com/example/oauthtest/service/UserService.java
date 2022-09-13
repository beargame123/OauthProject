package com.example.oauthtest.service;

import com.example.oauthtest.dto.request.UserRequest;
import com.example.oauthtest.entity.User;
import com.example.oauthtest.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public UserRequest myPage(String email){
        User user = userRepository.findByEmail(email).orElseThrow(() -> new BadCredentialsException("NOT_FOUND_USER"));
        return UserRequest.builder()
                .email(user.getEmail())
                .introduce(user.getIntroduce()).build();
    }

    public String leave(String email){
        User user = userRepository.findByEmail(email).orElseThrow(() -> new BadCredentialsException("NOT_FOUND_USER"));
        userRepository.delete(user);
        return "계정이 삭제되었습니다.";
    }
}
