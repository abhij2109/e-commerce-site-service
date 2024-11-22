package com.abhi.ecom.repository;

import com.abhi.ecom.models.Order;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrderRepository extends JpaRepository<Order, Long> {
}
