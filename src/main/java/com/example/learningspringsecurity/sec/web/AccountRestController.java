package com.example.learningspringsecurity.sec.web;


import com.example.learningspringsecurity.sec.dto.RoleUserForm;
import com.example.learningspringsecurity.sec.entity.AppRole;
import com.example.learningspringsecurity.sec.entity.AppUser;
import com.example.learningspringsecurity.sec.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping
public class AccountRestController {

    private final AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }
    @GetMapping("/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> getAllUsers()
    {
        return accountService.listUsers();
    }


    @PostMapping("/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser)
    {
        return accountService.addNewUser(appUser);
    }

    @PostMapping("/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole)
    {
        return accountService.addNewRole(appRole);
    }

    @GetMapping("/roles")
    public List<AppRole> getAllRoles()
    {
        return accountService.getAllRoles();
    }

    @PostMapping("/addRoleToUser")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm)
    {
         accountService.addRoleToUser(roleUserForm.getUserName(),roleUserForm.getRoleName());
    }
}
