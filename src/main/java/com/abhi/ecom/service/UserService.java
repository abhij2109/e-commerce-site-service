package com.abhi.ecom.service;

import com.abhi.ecom.exceptions.UserException;
import com.abhi.ecom.models.User;

public interface UserService {

    public User findUserById(Long id) throws UserException;

    public User findUserByJwt(String jwtToken) throws UserException;
}
