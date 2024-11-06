package com.abhi.ecom.service.implementations;

import com.abhi.ecom.config.JwtProvider;
import com.abhi.ecom.exceptions.UserException;
import com.abhi.ecom.models.User;
import com.abhi.ecom.repository.UserRepository;
import com.abhi.ecom.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserServiceImplementation implements UserService {

    private final UserRepository userRepository;
    private final JwtProvider jwtProvider;

    @Override
    public User findUserById(Long id) throws UserException {
        Optional<User> user = userRepository.findById(id);
        if(user.isPresent()){
            return user.get();
        }
        throw new UserException("User not found with id: "+ id);
    }

    @Override
    public User findUserByJwt(String jwtToken) throws UserException {
        String email = jwtProvider.getEmailFromToken(jwtToken);
        User user = userRepository.findByEmail(email);
        if(user == null)
            throw new UserException("User not found with email: "+email);
        return user;
    }
}
