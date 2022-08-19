package com.example.learningspringsecurity.sec.service;

import com.example.learningspringsecurity.sec.entity.AppRole;
import com.example.learningspringsecurity.sec.entity.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String  userName, String roleName);
    AppUser loadUserByUserName(String userName);
    List<AppUser> listUsers();

    List<AppRole> getAllRoles();
}
