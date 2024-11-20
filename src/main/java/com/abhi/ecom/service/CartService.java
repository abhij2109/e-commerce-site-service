package com.abhi.ecom.service;

import com.abhi.ecom.exceptions.ProductException;
import com.abhi.ecom.models.Cart;
import com.abhi.ecom.models.User;
import com.abhi.ecom.request.AddItemRequest;

public interface CartService {

    public Cart createCart(User user);
    public String addCartItem(Long userId, AddItemRequest request) throws ProductException;
    public Cart findUserCart(Long userId);
}
