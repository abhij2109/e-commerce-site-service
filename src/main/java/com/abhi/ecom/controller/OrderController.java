package com.abhi.ecom.controller;

import com.abhi.ecom.exceptions.UserException;
import com.abhi.ecom.models.Address;
import com.abhi.ecom.models.Order;
import com.abhi.ecom.models.User;
import com.abhi.ecom.service.OrderService;
import com.abhi.ecom.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/orders")
public class OrderController {

    private OrderService orderService;
    private UserService userService;

    @PostMapping("/")
    public ResponseEntity<Order> createOrder(@RequestBody Address shippingAddress,
                                             @RequestHeader("Authorization") String jwt) throws UserException {
        User user = userService.findUserByJwt(jwt);
        Order createdOrder = orderService.createOrder(user, shippingAddress);

        return new ResponseEntity<>(createdOrder, HttpStatus.CREATED);
    }
}
