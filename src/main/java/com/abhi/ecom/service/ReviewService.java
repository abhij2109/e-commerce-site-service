package com.abhi.ecom.service;

import com.abhi.ecom.exceptions.ProductException;
import com.abhi.ecom.models.Review;
import com.abhi.ecom.models.User;
import com.abhi.ecom.request.ReviewRequest;

import java.util.List;

public interface ReviewService {

    public Review createReview(ReviewRequest req, User user)throws ProductException;
    public List<Review> getAllReviews(Long productId);
}
