package com.abhi.ecom.service.implementations;

import com.abhi.ecom.exceptions.ProductException;
import com.abhi.ecom.models.Product;
import com.abhi.ecom.models.Rating;
import com.abhi.ecom.models.User;
import com.abhi.ecom.repository.RatingRepository;
import com.abhi.ecom.request.RatingRequest;
import com.abhi.ecom.service.ProductService;
import com.abhi.ecom.service.RatingService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class RatingServiceImplementation implements RatingService {

    private final RatingRepository ratingRepository;
    private final ProductService productService;
    @Override
    public Rating createRating(RatingRequest req, User user) throws ProductException {

        Product product = productService.findProductById(req.getProductId());

        Rating rating = new Rating();
        rating.setProduct(product);
        rating.setUser(user);
        rating.setRating(req.getRating());
        rating.setCreatedAt(LocalDateTime.now());

        return ratingRepository.save(rating);
    }

    @Override
    public List<Rating> getProductsRating(Long productId) {
        return ratingRepository.getProductsRating(productId);
    }
}
