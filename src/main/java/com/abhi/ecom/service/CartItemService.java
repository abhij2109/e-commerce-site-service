package com.abhi.ecom.service;

import com.abhi.ecom.exceptions.CartItemException;
import com.abhi.ecom.exceptions.UserException;
import com.abhi.ecom.models.Cart;
import com.abhi.ecom.models.CartItem;
import com.abhi.ecom.models.Product;

public interface CartItemService {

    public CartItem createCartItem(CartItem cartItem);
    public CartItem updateCartItem(Long userId, Long id, CartItem cartItem) throws CartItemException, UserException;
    public CartItem isCartItemExists(Cart cart, Product product, String size, Long userId);
    public void removeCartItem(Long userId, Long cartItemId) throws CartItemException, UserException;
    public CartItem findCartItemById(Long cartItemId)throws CartItemException;
}
