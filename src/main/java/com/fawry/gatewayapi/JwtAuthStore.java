package com.fawry.gatewayapi;

import java.util.*;

import com.fawry.gatewayapi.dto.*;
import org.springframework.cloud.gateway.filter.*;
import org.springframework.cloud.gateway.filter.factory.*;
import org.springframework.http.*;
import org.springframework.http.server.reactive.*;
import org.springframework.stereotype.*;
import org.springframework.web.reactive.function.client.*;
import org.springframework.web.server.*;
import reactor.core.publisher.*;

@Component
public class JwtAuthStore extends AbstractGatewayFilterFactory<JwtAuthStore.Config> {
    private final WebClient.Builder webClient;

    public JwtAuthStore(WebClient.Builder webClient) {
        super(Config.class);
        this.webClient = webClient;
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Collections.emptyList();
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return handleUnauthorized(exchange, "Missing or invalid Authorization header");
            }

            String token = authHeader.substring(7); // Extract token

            return webClient.build().get()
                    .uri("lb://USER-API/api/token/admin/validation")
                    .headers(httpHeaders -> httpHeaders.setBearerAuth(token))
                    .exchangeToMono(clientResponse -> {
                        if (clientResponse.statusCode().equals(HttpStatus.OK)) {
                            return clientResponse.bodyToMono(UserClaimsDTO.class)
                                    .flatMap(claims -> forwardRequestWithClaims(exchange, chain, claims));
                        }
                        return clientResponse.bodyToMono(String.class).flatMap(error -> handleUnauthorized(exchange, error));
                    });
        };
    }

    private Mono<Void> forwardRequestWithClaims(ServerWebExchange exchange, GatewayFilterChain chain, UserClaimsDTO claims) {
        ServerWebExchange modifiedExchange = exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .headers(httpHeaders -> {
                            httpHeaders.set("UserId", claims.UserId());
                            httpHeaders.set("Email", claims.Email());
                            httpHeaders.set("Role", claims.Role());
                        })
                        .build())
                .build();

        return chain.filter(modifiedExchange);
    }

    private Mono<Void> handleUnauthorized(ServerWebExchange exchange, String error) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] errorBytes = error.getBytes();
        return response.writeWith(Mono.just(response.bufferFactory().wrap(errorBytes)));
    }

    public static class Config {
    }
}