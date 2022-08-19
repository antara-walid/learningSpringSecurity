package com.example.learningspringsecurity.sec.repository;

import com.example.learningspringsecurity.sec.entity.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser,Long> {
    AppUser findByUserName(String userName);
}
