package br.com.javamoon.foro11apiauth.core.security;

import java.util.Collections;

import org.springframework.security.core.userdetails.User;

public class AuthUser extends User{

	public AuthUser(br.com.javamoon.foro11apiauth.domain.User user) {
		super(user.getEmail(), user.getPassword(), Collections.emptyList());
	}
}
