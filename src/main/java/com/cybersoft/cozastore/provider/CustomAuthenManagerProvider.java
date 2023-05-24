package com.cybersoft.cozastore.provider;

import com.cybersoft.cozastore.entity.UserEntity;
import com.cybersoft.cozastore.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class CustomAuthenManagerProvider implements AuthenticationProvider {

    @Autowired
    UserRepository userRepository;

    @Autowired
    @Lazy // de load sau
    PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // lay username nguoi dung truyen len
        String username = authentication.getName();
        // lay password nguoi dung truyen len
        String password = authentication.getCredentials().toString();
        UserEntity user = userRepository.findByUsername(username);
        if (user != null){
            // so sanh password nguoi dung truyen vao voi password BCrypt luu trong database
            if(passwordEncoder.matches(password, user.getPassword())){
                // trung password
                return new UsernamePasswordAuthenticationToken(username, user.getPassword(), new ArrayList<>());
            }
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
