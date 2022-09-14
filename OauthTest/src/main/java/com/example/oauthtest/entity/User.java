package com.example.oauthtest.entity;

import com.example.oauthtest.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Table(name = "USERS")
public class User {
    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "email")
    private String email;

    @Column(name = "password")
    private String password;

    @Column(name = "introduce")
    private String introduce;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Builder
    public User(String email, String password, String introduce, Role role){
        this.email = email;
        this.password = password;
        this.introduce = introduce;
        this.role = role;
    }
}
