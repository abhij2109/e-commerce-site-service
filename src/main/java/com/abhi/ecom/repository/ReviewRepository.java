package com.abhi.ecom.repository;

import com.abhi.ecom.models.Review;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ReviewRepository extends JpaRepository<Review, Long> {

    @Query("Select r from Review r where r.product.id = :productId")
    public List<Review> getAllProductsReview(@Param("productId") Long productId);
}
