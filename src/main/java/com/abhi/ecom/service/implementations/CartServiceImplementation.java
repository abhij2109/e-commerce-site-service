package com.abhi.ecom.service.implementations;

import com.abhi.ecom.constants.Constants;
import com.abhi.ecom.exceptions.ProductException;
import com.abhi.ecom.models.Cart;
import com.abhi.ecom.models.CartItem;
import com.abhi.ecom.models.Product;
import com.abhi.ecom.models.User;
import com.abhi.ecom.repository.CartRepository;
import com.abhi.ecom.request.AddItemRequest;
import com.abhi.ecom.service.CartItemService;
import com.abhi.ecom.service.CartService;
import com.abhi.ecom.service.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CartServiceImplementation implements CartService {

    private final CartRepository cartRepository;
    private final CartItemService cartItemService;
    private final ProductService productService;

    @Override
    public Cart createCart(User user) {
        Cart cart = new Cart();
        cart.setUser(user);
        return cartRepository.save(cart);
    }

    @Override
    public String addCartItem(Long userId, AddItemRequest request) throws ProductException {

        Cart cart = cartRepository.findByUserId(userId);
        Product product = productService.findProductById(request.getProductId());
        CartItem isPresent = cartItemService.isCartItemExists(cart, product, request.getSize(), userId);

        if(isPresent == null){

            CartItem item = new CartItem();
            item.setProduct(product);
            item.setCart(cart);
            item.setQuantity(request.getQuantity());
            item.setUserId(userId);

            int price = request.getQuantity() * product.getDiscounted_price();
            item.setPrice(price);
            item.setSize(request.getSize());

            CartItem createdCartItems = cartItemService.createCartItem(item);
            cart.getCartItems().add(createdCartItems);
        }
        return Constants.ITEM_ADDED_IN_CART;
    }

    @Override
    public Cart findUserCart(Long userId) {

        Cart cart = cartRepository.findByUserId(userId);

        int totalPrice = 0;
        int totalDiscountedPrice = 0;
        int totalItem=0;
        for(CartItem item:cart.getCartItems()){
               totalPrice = totalPrice + item.getPrice();
               totalDiscountedPrice = (int) (totalDiscountedPrice + item.getDiscountedPrice());
               totalItem = totalItem + item.getQuantity();
        }
        cart.setTotalPrice(totalPrice);
        cart.setTotalItem(totalItem);
        cart.setTotalDiscountedPrice(totalDiscountedPrice);
        cart.setDiscount(totalPrice-totalDiscountedPrice);

        return cartRepository.save(cart);
    }
}
