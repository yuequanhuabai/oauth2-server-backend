package com.t.a.oauth2server.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "oauth2_clients")
@NoArgsConstructor
@AllArgsConstructor
@Data
public class Client {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String clientId;

    @Column(nullable = false)
    private String clientSecret;

    @Column(name = "redirect_uri")
    private String redirectUri;

    @Column(name = "scope")
    private String scope;

    @Column(name = "authorized_grant_types")
    private String authorizedGrantTypes;

    @Column(name = "access_token_validity_seconds")
    private Integer accessTokenValiditySeconds;

    @Column(name = "refresh_token_validity_seconds")
    private Integer refreshTokenValiditySeconds;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;
}
