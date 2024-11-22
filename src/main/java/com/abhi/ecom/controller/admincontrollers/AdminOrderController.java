package com.abhi.ecom.controller.admincontrollers;

import com.abhi.ecom.constants.Constants;
import com.abhi.ecom.exceptions.OrderException;
import com.abhi.ecom.models.Order;
import com.abhi.ecom.response.ApiResponse;
import com.abhi.ecom.service.OrderService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/admin/orders")
public class AdminOrderController {

    private final OrderService orderService;

    @GetMapping("/")
    public ResponseEntity<List<Order>> getAllOrdersHandler(){
        List<Order> orders = orderService.getAllOrders();

        return new ResponseEntity<List<Order>>(orders, HttpStatus.ACCEPTED);
    }

    @PutMapping("/{orderId}/confirmed")
    public ResponseEntity<Order> confirmOrderHandler(@PathVariable Long orderId,
                                                     @RequestHeader("Authorization") String jwt) throws OrderException{
        Order order = orderService.confirmedOrder(orderId);
        return new ResponseEntity<>(order, HttpStatus.OK);
    }

    @PutMapping("/{orderId}/shipped")
    public ResponseEntity<Order> shippedOrderHandler(@PathVariable Long orderId,
                                                     @RequestHeader("Authorization") String jwt) throws OrderException{
        Order order = orderService.shippedOrder(orderId);
        return new ResponseEntity<>(order, HttpStatus.OK);
    }

    @PutMapping("/{orderId}/deliver")
    public ResponseEntity<Order> deliveryOrderHandler(@PathVariable Long orderId,
                                                     @RequestHeader("Authorization") String jwt) throws OrderException {
        Order order = orderService.deliveredOrder(orderId);
        return new ResponseEntity<>(order, HttpStatus.OK);
    }

    @PutMapping("/{orderId}/cancel")
    public ResponseEntity<Order> cancelOrderHandler(@PathVariable Long orderId,
                                                      @RequestHeader("Authorization") String jwt) throws OrderException {
        Order order = orderService.canceledOrder(orderId);
        return new ResponseEntity<>(order, HttpStatus.OK);
    }

    @DeleteMapping("/{orderId}/delete")
    public ResponseEntity<ApiResponse> deleteOrderHandler(@PathVariable Long orderId,
                                                         @RequestHeader("Authorization") String jwt) throws OrderException {

        orderService.deleteOrder(orderId);
        ApiResponse response = new ApiResponse();
        response.setMessage(Constants.ORDER_DELETED);
        response.setStatus(Constants.TRUE);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }



}
