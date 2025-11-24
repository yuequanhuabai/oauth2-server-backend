package com.t.a.oauth2server.controller;

import com.t.a.oauth2server.conf.DataStore;
import com.t.a.oauth2server.pojo.AccessToken;
import com.t.a.oauth2server.pojo.AuthCode;
import com.t.a.oauth2server.pojo.ClientInfo;
import com.t.a.oauth2server.pojo.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
public class OAuth2Controller {

    @Autowired
    private DataStore dataStore;

    // 步骤1: 授权端点 - 验证客户端并返回授权页面所需信息
    @GetMapping("/oauth/authorize")
    public ResponseEntity<Map<String, Object>> authorize(
            @RequestParam String client_id,
            @RequestParam String redirect_uri,
            @RequestParam String response_type,
            @RequestParam(required = false) String state) {

        Map<String, Object> response = new HashMap<>();

        // 验证客户端
        ClientInfo client = dataStore.getClients().get(client_id);
        if (client == null || !client.getRedirectUri().equals(redirect_uri)) {
            response.put("error", "invalid_client");
            return ResponseEntity.badRequest().body(response);
        }

        // 返回授权信息供前端使用
        response.put("client_id", client_id);
        response.put("redirect_uri", redirect_uri);
        response.put("state", state);
        response.put("valid", true);

        return ResponseEntity.ok(response);
    }

    // 步骤2: 登录端点 - 验证用户并生成授权码
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> request) {

        Map<String, Object> response = new HashMap<>();

        String username = request.get("username");
        String password = request.get("password");
        String clientId = request.get("client_id");
        String redirectUri = request.get("redirect_uri");
        String state = request.get("state");

        // 验证用户凭证
        User user = dataStore.getUsers().get(username);
        if (user == null || !user.getPassword().equals(password)) {
            response.put("error", "invalid_credentials");
            response.put("message", "用户名或密码错误");
            return ResponseEntity.status(401).body(response);
        }

        // 生成授权码
        String code = UUID.randomUUID().toString();
        AuthCode authCode = AuthCode.builder()
                .code(code)
                .clientId(clientId)
                .username(username)
                .expireTime(System.currentTimeMillis() + 600000)
                .build();

        dataStore.getAuthCodes().put(code, authCode);

        // 构建重定向URL
        String redirectUrl = redirectUri + "?code=" + code;
        if (state != null && !state.isEmpty()) {
            redirectUrl += "&state=" + state;
        }

        response.put("redirect_url", redirectUrl);
        return ResponseEntity.ok(response);
    }

    // 步骤3: 令牌端点 - 授权码换取访问令牌
    @PostMapping("/oauth/token")
    public ResponseEntity<Map<String, Object>> token(@RequestBody Map<String, String> request) {

        Map<String, Object> response = new HashMap<>();

        String grantType = request.get("grant_type");
        String code = request.get("code");
        String clientId = request.get("client_id");
        String clientSecret = request.get("client_secret");

        // 验证客户端凭证
        ClientInfo client = dataStore.getClients().get(clientId);
        if (client == null || !client.getClientSecret().equals(clientSecret)) {
            response.put("error", "invalid_client");
            return ResponseEntity.status(401).body(response);
        }

        // 验证授权码
        AuthCode authCode = dataStore.getAuthCodes().get(code);
        if (authCode == null || authCode.getExpireTime() < System.currentTimeMillis()) {
            response.put("error", "invalid_grant");
            return ResponseEntity.badRequest().body(response);
        }

        // 生成访问令牌
        String accessToken = UUID.randomUUID().toString();
        AccessToken token = new AccessToken(accessToken, clientId, authCode.getUsername(),
                System.currentTimeMillis() + 3600000);
        dataStore.getAccessTokens().put(accessToken, token);

        // 删除已使用的授权码
        dataStore.getAuthCodes().remove(code);

        // 返回令牌响应
        response.put("access_token", accessToken);
        response.put("token_type", "Bearer");
        response.put("expires_in", 3600);

        return ResponseEntity.ok(response);
    }

    // 步骤4: 用户信息端点
    @GetMapping("/oauth/userinfo")
    public ResponseEntity<Map<String, Object>> userinfo(@RequestHeader("Authorization") String authorization) {

        Map<String, Object> response = new HashMap<>();

        if (!authorization.startsWith("Bearer ")) {
            response.put("error", "invalid_token");
            return ResponseEntity.status(401).body(response);
        }

        String tokenValue = authorization.substring(7);
        AccessToken token = dataStore.getAccessTokens().get(tokenValue);

        if (token == null || token.getExpireTime() < System.currentTimeMillis()) {
            response.put("error", "invalid_token");
            return ResponseEntity.status(401).body(response);
        }

        User user = dataStore.getUsers().get(token.getUsername());
        response.put("sub", user.getUsername());
        response.put("name", user.getDisplayName());
        response.put("username", user.getUsername());

        return ResponseEntity.ok(response);
    }
}
