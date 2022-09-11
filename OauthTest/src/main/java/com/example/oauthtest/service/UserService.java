package com.example.oauthtest.service;

import com.example.oauthtest.dto.request.UserRequest;
import com.example.oauthtest.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public UserRequest myPage(String email){

    }
}
