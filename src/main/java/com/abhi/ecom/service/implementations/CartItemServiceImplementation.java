package com.abhi.ecom.service.implementations;

import com.abhi.ecom.exceptions.CartItemException;
import com.abhi.ecom.exceptions.UserException;
import com.abhi.ecom.models.Cart;
import com.abhi.ecom.models.CartItem;
import com.abhi.ecom.models.Product;
import com.abhi.ecom.models.User;
import com.abhi.ecom.repository.CartItemRepository;
import com.abhi.ecom.service.CartItemService;
import com.abhi.ecom.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CartItemServiceImplementation implements CartItemService {

    private final CartItemRepository cartItemRepository;
    private final UserService userService;

    @Override
    public CartItem createCartItem(CartItem cartItem) {

        cartItem.setQuantity(1);
        cartItem.setPrice(cartItem.getProduct().getPrice() * cartItem.getQuantity());
        cartItem.setDiscountedPrice(cartItem.getProduct().getDiscounted_price() * cartItem.getQuantity());

        return cartItemRepository.save(cartItem);
    }

    @Override
    public CartItem updateCartItem(Long userId, Long id, CartItem cartItem) throws CartItemException, UserException {

        CartItem item = findCartItemById(id);
        User user = userService.findUserById(userId);

        if(user.getUserId().equals(userId)){
            item.setQuantity(cartItem.getQuantity());
            item.setPrice(item.getQuantity() * item.getProduct().getPrice());
            item.setDiscountedPrice(item.getProduct().getDiscounted_price() * item.getQuantity());
        }

        return cartItemRepository.save(cartItem);
    }

    @Override
    public CartItem isCartItemExists(Cart cart, Product product, String size, Long userId) {
        return cartItemRepository.isCartItemExist(cart, product, size, userId);
    }

    @Override
    public void removeCartItem(Long userId, Long cartItemId) throws CartItemException, UserException {

        CartItem cartItem = findCartItemById(cartItemId);

        User user = userService.findUserById(cartItem.getUserId());
        User requestUser = userService.findUserById(userId);

        if(user.getUserId().equals(requestUser.getUserId())){
            cartItemRepository.deleteById(cartItemId);
        }
        else{
            throw new UserException("You can't remove another user's items.");
        }
    }

    @Override
    public CartItem findCartItemById(Long cartItemId) throws CartItemException {
        Optional<CartItem> opt = cartItemRepository.findById(cartItemId);
        return opt.orElseThrow(()-> new CartItemException("Cart Item not found with id: "+cartItemId));
    }
}
