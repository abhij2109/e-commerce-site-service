package com.abhi.ecom.service.implementations;

import com.abhi.ecom.exceptions.ProductException;
import com.abhi.ecom.models.Product;
import com.abhi.ecom.models.Review;
import com.abhi.ecom.models.User;
import com.abhi.ecom.repository.ReviewRepository;
import com.abhi.ecom.request.ReviewRequest;
import com.abhi.ecom.service.ProductService;
import com.abhi.ecom.service.ReviewService;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
@Service
@RequiredArgsConstructor
public class ReviewServiceImplementation implements ReviewService {

    private final ReviewRepository reviewRepository;
    private final ProductService productService;

    @Override
    public Review createReview(ReviewRequest req, User user) throws ProductException {
        Product product = productService.findProductById(req.getProductId());

        Review review = new Review();
        review.setUser(user);
        review.setProduct(product);
        review.setReview(req.getReview());
        review.setCreatedAt(LocalDateTime.now());

        return reviewRepository.save(review);
    }

    @Override
    public List<Review> getAllReviews(Long productId) {
        return reviewRepository.getAllProductsReview(productId);
    }
}
