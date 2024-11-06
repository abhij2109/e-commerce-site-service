package com.abhi.ecom.repository;

import com.abhi.ecom.models.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ProductRepository extends JpaRepository<Product, Long> {

    @Query("select * from product p " +
            "where(p.category_name = :category or :category = '') " +
            "and ((:minPrice is null and :maxPrice is null) or (p.discounted_price between :minPrice and :maxPrice)) " +
            "and (:minDiscount is null or p.discount_percent>=:minDiscount) " +
            "order by " +
            "case when :sort = 'price_low' then p.discounted_price end asc, " +
            "case when :sort = 'price_high' then p.discounted_price end desc;")
    public List<Product> filterProducts(@Param("category") String category,
                                        @Param("minPrice") Integer minPrice,
                                        @Param("maxPrice") Integer maxPrice,
                                        @Param("minDiscount") Integer minDiscount,
                                        @Param("sort") String sort);
}
