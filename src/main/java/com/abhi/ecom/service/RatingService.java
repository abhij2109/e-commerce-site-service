package com.abhi.ecom.service;

import com.abhi.ecom.exceptions.ProductException;
import com.abhi.ecom.models.Rating;
import com.abhi.ecom.models.User;
import com.abhi.ecom.request.RatingRequest;

import java.util.List;

public interface RatingService {

    public Rating createRating(RatingRequest req, User user)throws ProductException;
    public List<Rating> getProductsRating(Long productId);
}
