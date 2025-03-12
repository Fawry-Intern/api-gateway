package com.fawry.gatewayapi;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;
import java.util.function.Function;

@Component
public class JwtAuthUser extends AbstractGatewayFilterFactory<JwtAuthUser.Config> {
    private final WebClient.Builder webClient;

    public JwtAuthUser(WebClient.Builder webClient) {
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
            String token;
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7);
            } else {
                token = "";
            }
            return webClient.build().get()
                    .uri("lb://USER-API/api/token/user/validation")
                    .headers(httpHeaders -> httpHeaders.setBearerAuth(token))
                    .exchangeToMono(clientResponse -> {
                        if (clientResponse.statusCode().equals(HttpStatus.OK)) {
                            return chain.filter(exchange);
                        }
                        Function<String, Mono<Void>> errorFun = error -> {
                            ServerHttpResponse response = exchange.getResponse();
                            response.setStatusCode(clientResponse.statusCode());
                            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
                            byte[] errorBytes = error.getBytes();
                            return response.writeWith(Mono.just(response.bufferFactory().wrap(errorBytes)));
                        };
                        return clientResponse.bodyToMono(String.class).flatMap(errorFun);
                    });
        };

    }
    public static class Config {

    }
}