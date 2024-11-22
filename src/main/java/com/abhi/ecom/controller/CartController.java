package com.abhi.ecom.controller;

import com.abhi.ecom.exceptions.ProductException;
import com.abhi.ecom.exceptions.UserException;
import com.abhi.ecom.models.Cart;
import com.abhi.ecom.models.User;
import com.abhi.ecom.request.AddItemRequest;
import com.abhi.ecom.response.ApiResponse;
import com.abhi.ecom.service.CartService;
import com.abhi.ecom.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/cart")
public class CartController {

    private final UserService userService;
    private final CartService cartService;

    @GetMapping("/")
    public ResponseEntity<Cart> findUserCart(@RequestHeader("Authorization") String jwt)throws UserException{

        User user = userService.findUserByJwt(jwt);
        Cart cart = cartService.findUserCart(user.getUserId());

        return new ResponseEntity<>(cart, HttpStatus.OK);
    }

    @PutMapping("/add")
    public ResponseEntity<ApiResponse> addItemToCart(@RequestBody AddItemRequest request,
                                                     @RequestHeader("Authorization") String jwt) throws ProductException, UserException{
        User user = userService.findUserByJwt(jwt);
        String itemAddedMessage = cartService.addCartItem(user.getUserId(), request);

        ApiResponse response = new ApiResponse();
        response.setMessage(itemAddedMessage);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
