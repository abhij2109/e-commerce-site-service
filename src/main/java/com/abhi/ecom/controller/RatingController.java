package com.abhi.ecom.controller;

import com.abhi.ecom.exceptions.ProductException;
import com.abhi.ecom.exceptions.UserException;
import com.abhi.ecom.models.Rating;
import com.abhi.ecom.models.User;
import com.abhi.ecom.request.RatingRequest;
import com.abhi.ecom.service.RatingService;
import com.abhi.ecom.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/ratings")
public class RatingController {

    private final RatingService ratingService;
    private final UserService userService;

    @PostMapping("/create")
    public ResponseEntity<Rating> createRating(@RequestBody RatingRequest request,
                                               @RequestHeader("Authorization") String jwt) throws UserException, ProductException {
        User user = userService.findUserByJwt(jwt);
        Rating rating = ratingService.createRating(request, user);

        return new ResponseEntity<>(rating, HttpStatus.CREATED);
    }

    @GetMapping("/product/{productId}")
    public ResponseEntity<List<Rating>> getProductsRating(@PathVariable Long productId){
        List<Rating> ratings = ratingService.getProductsRating(productId);

        return new ResponseEntity<>(ratings, HttpStatus.ACCEPTED);
    }
}
