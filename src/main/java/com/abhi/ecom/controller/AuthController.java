package com.abhi.ecom.controller;

import com.abhi.ecom.config.JwtProvider;
import com.abhi.ecom.constants.Constants;
import com.abhi.ecom.exceptions.UserException;
import com.abhi.ecom.models.Cart;
import com.abhi.ecom.models.User;
import com.abhi.ecom.repository.UserRepository;
import com.abhi.ecom.request.LoginRequest;
import com.abhi.ecom.response.AuthResponse;
import com.abhi.ecom.service.CartService;
import com.abhi.ecom.service.implementations.CustomUserServiceImplementation;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
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
    private final CustomUserServiceImplementation serviceImplementation;
    private final CartService cartService;

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
        Cart cart = cartService.createCart(savedUser);

        Authentication authentication = new UsernamePasswordAuthenticationToken(savedUser.getEmail(), savedUser.getPassWord());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtProvider.generateToken(authentication);

        AuthResponse authResponse = new AuthResponse();
        authResponse.setToken(token);
        authResponse.setMessage(Constants.SINGUP_SUCCESSFUL);

        return new ResponseEntity<AuthResponse>(authResponse, HttpStatus.CREATED);
    }

    @PostMapping("/logIn")
    public ResponseEntity<AuthResponse> loginUserHandler(@RequestBody LoginRequest request){
        String userName = request.getUserName();
        String passWord = request.getPassWord();

        Authentication authentication = authenticate(userName, passWord);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtProvider.generateToken(authentication);

        AuthResponse authResponse = new AuthResponse();
        authResponse.setToken(token);
        authResponse.setMessage(Constants.LOGIN_SUCCESSFUL);

        return new ResponseEntity<AuthResponse>(authResponse, HttpStatus.OK);
    }

    private Authentication authenticate(String userName, String passWord) {
        UserDetails userDetails = serviceImplementation.loadUserByUsername(userName);
        if(userDetails == null){
            throw new BadCredentialsException("Invalid Username...");
        }
        if(!passwordEncoder.matches(passWord, userDetails.getPassword())){
            throw new BadCredentialsException("Invalid Password...");
        }
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }
}
