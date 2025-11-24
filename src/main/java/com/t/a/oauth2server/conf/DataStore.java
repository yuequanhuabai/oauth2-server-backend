package com.t.a.oauth2server.conf;

import com.t.a.oauth2server.pojo.AccessToken;
import com.t.a.oauth2server.pojo.AuthCode;
import com.t.a.oauth2server.pojo.ClientInfo;
import com.t.a.oauth2server.pojo.User;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Data
@Component
public class DataStore {
    private final Map<String, ClientInfo> clients = new HashMap<>();
    private final Map<String, User> users = new HashMap<>();
    private final Map<String, AuthCode> authCodes = new HashMap<>();
    private final Map<String, AccessToken> accessTokens = new HashMap<>();

    @PostConstruct
    public void init() {
        clients.put("client123", new ClientInfo("client123", "secret456",
                "http://localhost:3001/callback"));

        users.put("admin", new User("admin", "123456", "管理员"));
    }
}
