package com.abhi.ecom.controller;

import com.abhi.ecom.exceptions.ProductException;
import com.abhi.ecom.exceptions.UserException;
import com.abhi.ecom.models.Review;
import com.abhi.ecom.models.User;
import com.abhi.ecom.request.ReviewRequest;
import com.abhi.ecom.service.ReviewService;
import com.abhi.ecom.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/reviews")
public class ReviewController {

    private final ReviewService reviewService;
    private final UserService userService;

    @PostMapping("/create")
    public ResponseEntity<Review> createReview(@RequestBody ReviewRequest request,
                                               @RequestHeader("Authorization") String jwt) throws UserException, ProductException {
        User user = userService.findUserByJwt(jwt);
        Review review = reviewService.createReview(request, user);

        return new ResponseEntity<>(review, HttpStatus.CREATED);
    }

    @GetMapping("/product/{productId}")
    public ResponseEntity<List<Review>> getProductsRating(@PathVariable Long productId){
        List<Review> reviews = reviewService.getAllReviews(productId);

        return new ResponseEntity<>(reviews, HttpStatus.ACCEPTED);
    }
}
