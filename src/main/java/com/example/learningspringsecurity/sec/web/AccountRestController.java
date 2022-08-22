package com.example.learningspringsecurity.sec.web;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.learningspringsecurity.sec.JWTUtil;
import com.example.learningspringsecurity.sec.dto.RoleUserForm;
import com.example.learningspringsecurity.sec.entity.AppRole;
import com.example.learningspringsecurity.sec.entity.AppUser;
import com.example.learningspringsecurity.sec.service.AccountService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping
@Slf4j
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

    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request , HttpServletResponse response) throws IOException {
        String authorizationToken = request.getHeader(JWTUtil.AUT_HEADER);
        if(authorizationToken != null && authorizationToken.startsWith(JWTUtil.PREFIX))
        {
            try {
                String jwt = authorizationToken.substring(JWTUtil.PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                String userName = decodedJWT.getSubject();
                log.info("userName :{}",userName);
                AppUser appUser = accountService.loadUserByUserName(userName);
                log.info("appUser : {}",appUser);
                // create token
                String jwtAccessToken = JWT.create()
                        .withSubject(appUser.getUserName())
                        .withExpiresAt(new Date(System.currentTimeMillis() + JWTUtil.EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getAppRoles().stream().map(role -> role.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String,String> idToken = new HashMap<>();
                idToken.put("access-token", jwtAccessToken);
                idToken.put("refresh-token", jwt);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);

            } catch (Exception ex) {
                throw ex;
            }
        }else {
            throw new RuntimeException("refresh token is required");
        }
    }

    @GetMapping("/profile")
    public AppUser profile(Authentication authentication)
    {
        log.info("profile name :{}", authentication.getName());
        return accountService.loadUserByUserName( authentication.getName());
    }
}
