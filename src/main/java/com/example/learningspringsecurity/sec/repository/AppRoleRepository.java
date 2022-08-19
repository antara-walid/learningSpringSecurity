package com.example.learningspringsecurity.sec.repository;

import com.example.learningspringsecurity.sec.entity.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole,Long> {
    AppRole findByRoleName(String roleName);
}
