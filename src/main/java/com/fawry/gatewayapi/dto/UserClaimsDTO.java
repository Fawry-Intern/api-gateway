package com.fawry.gatewayapi.dto;

public record UserClaimsDTO
        (
                String UserId,
                String Email,
                String  Role

        ) {
}
