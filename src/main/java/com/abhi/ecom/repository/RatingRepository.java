package com.abhi.ecom.repository;

import com.abhi.ecom.models.Rating;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface RatingRepository extends JpaRepository<Rating, Long> {

    @Query("Select r from Rating r where r.product.id = :productId")
    public List<Rating> getProductsRating(@Param("productId") Long productId);
}
