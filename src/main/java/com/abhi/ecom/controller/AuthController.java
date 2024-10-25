package com.abhi.ecom.controller;

import com.abhi.ecom.config.JwtProvider;
import com.abhi.ecom.constants.Constants;
import com.abhi.ecom.exceptions.UserException;
import com.abhi.ecom.models.User;
import com.abhi.ecom.repository.UserRepository;
import com.abhi.ecom.response.AuthResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final JwtProvider jwtProvider;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/signUp")
    public ResponseEntity<AuthResponse> createUserHandler(@RequestBody User user)throws UserException{
        String email = user.getEmail();
        String password = user.getPassWord();
        String firstNameString = user.getFirstName();
        String lastNameString = user.getLastName();

        User isEmailAlreadyExists = userRepository.findByEmail(email);
        if(isEmailAlreadyExists!=null) {
            throw new UserException("Email is already used.");
        }

        User userToBeCreated = new User();
        userToBeCreated.setEmail(email);
        userToBeCreated.setPassWord(passwordEncoder.encode(password));
        userToBeCreated.setFirstName(firstNameString);
        userToBeCreated.setLastName(lastNameString);

        User savedUser = userRepository.save(userToBeCreated);

        Authentication authentication = new UsernamePasswordAuthenticationToken(savedUser.getEmail(), savedUser.getPassWord());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtProvider.generateToken(authentication);

        AuthResponse authResponse = new AuthResponse(token, Constants.SINGUP_SUCCESSFULL);

        return new ResponseEntity<AuthResponse>(authResponse, HttpStatus.CREATED);
    }
}
