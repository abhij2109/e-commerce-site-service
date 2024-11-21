package com.abhi.ecom.repository;

import com.abhi.ecom.models.Cart;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CartRepository extends JpaRepository<Cart, Long> {

    @Query("Select c from Cart c where c.user.id = :userId")
    public Cart findByUserId(@Param("userId") Long userId);
}
