package com.abhi.ecom.repository;

import com.abhi.ecom.models.Cart;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CartRepository extends JpaRepository<Cart, Long> {

    @Query("Select c from cart c where c.user.id = :userId")
    Cart findByUserId(@Param("userId") Long userId);
}
