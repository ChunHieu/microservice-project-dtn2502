package vti.dtn.api_gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {

    @Bean
    public RouteLocator route(RouteLocatorBuilder builder){
        return builder.routes()
                .route("account-service", r -> r.path("/api/v1/accounts/**")
                        .uri("lb://account-service")) // Gửi đến service tên là account-service thông qua Load Balancer

                .route("department-service", r -> r.path("/api/v1/departments/**")
                        .uri("lb://department-service")) // Gửi đến department-service
                .build();

    }
}
