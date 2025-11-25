package com.t.a.oauth2server.controller;

import com.t.a.oauth2server.entity.User;
import com.t.a.oauth2server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class OAuth2Controller {
    private final UserRepository userRepository;

    @GetMapping("/userinfo")
    public ResponseEntity<?> userinfo(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // 如果是OAuth2用戶（來自JWT令牌）
        if (authentication instanceof BearerTokenAuthentication) {
            String username = authentication.getName();
            User user = userRepository.findByUsername(username).orElse(null);
            if (user != null) {
                Map<String, Object> userInfo = new HashMap<>();
                userInfo.put("sub", user.getUsername());
                userInfo.put("name", user.getDisplayName());
                userInfo.put("email", user.getEmail());
                return ResponseEntity.ok(userInfo);
            }
        }

        // 如果是OIDC用戶
        if (authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            return ResponseEntity.ok(oidcUser.getAttributes());
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "用户已存在"));
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(request.getPassword());
        user.setDisplayName(request.getDisplayName());
        user.setEmail(request.getEmail());
        user.setEnabled(true);

        userRepository.save(user);
        return ResponseEntity.ok(Map.of("message", "註冊成功"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login() {
        // 登錄由Spring Security處理，此端點已被棄用
        // 用戶應該通過/authorize端點進行OAuth2登錄
        return ResponseEntity.badRequest().body(Map.of(
            "error", "Please use OAuth2 authorization code flow",
            "info", "Visit /oauth/authorize with proper parameters"
        ));
    }

    public static class RegisterRequest {
        public String username;
        public String password;
        public String displayName;
        public String email;

        public String getUsername() { return username; }
        public String getPassword() { return password; }
        public String getDisplayName() { return displayName; }
        public String getEmail() { return email; }
    }
}
