package com.fawry.gatewayapi;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;
import java.util.function.Function;

@Component
public class JwtAuthAdmin extends AbstractGatewayFilterFactory<JwtAuthAdmin.Config> {
    private final WebClient.Builder webClient;

    public JwtAuthAdmin(WebClient.Builder webClient) {
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
                            return clientResponse.bodyToMono(String.class)
                                    .flatMap(userId -> forwardRequestWithUserId(exchange, chain, userId));
                        }
                        return clientResponse.bodyToMono(String.class).flatMap(error -> handleUnauthorized(exchange, error));
                    });
        };
    }

    private Mono<Void> forwardRequestWithUserId(ServerWebExchange exchange, GatewayFilterChain chain, String userId) {
        ServerWebExchange modifiedExchange = exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .header("UserId", userId)  // Injecting UserId as header
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
