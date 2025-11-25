package com.t.a.oauth2server.config;

import com.t.a.oauth2server.entity.Role;
import com.t.a.oauth2server.entity.User;
import com.t.a.oauth2server.repository.RoleRepository;
import com.t.a.oauth2server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class DataInitializer {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @EventListener(ApplicationReadyEvent.class)
    public void initializeData() {
        // 初始化角色
        if (roleRepository.findByName("ADMIN").isEmpty()) {
            Role adminRole = new Role();
            adminRole.setName("ADMIN");
            adminRole.setDescription("管理員");
            roleRepository.save(adminRole);
        }

        if (roleRepository.findByName("USER").isEmpty()) {
            Role userRole = new Role();
            userRole.setName("USER");
            userRole.setDescription("普通用戶");
            roleRepository.save(userRole);
        }

        // 初始化用戶
        if (userRepository.findByUsername("admin").isEmpty()) {
            Role adminRole = roleRepository.findByName("ADMIN").orElseThrow();
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("123456"));
            admin.setDisplayName("管理員");
            admin.setEmail("admin@example.com");
            admin.setEnabled(true);
            admin.setRoles(Set.of(adminRole));
            userRepository.save(admin);
        }

        if (userRepository.findByUsername("user").isEmpty()) {
            Role userRole = roleRepository.findByName("USER").orElseThrow();
            User user = new User();
            user.setUsername("user");
            user.setPassword(passwordEncoder.encode("password123"));
            user.setDisplayName("普通用戶");
            user.setEmail("user@example.com");
            user.setEnabled(true);
            user.setRoles(Set.of(userRole));
            userRepository.save(user);
        }
    }
}
