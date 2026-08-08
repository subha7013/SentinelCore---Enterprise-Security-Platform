# Multi-stage Dockerfile for SentinelCore Spring Boot Backend

# Stage 1: Build the Jar with Gradle
FROM gradle:8.8-jdk21 AS build
WORKDIR /app

# Copy gradle wrapper and dependency specs first for caching
COPY build.gradle settings.gradle /app/
COPY gradle /app/gradle/
COPY gradlew /app/

# Fetch dependencies
RUN gradle dependencies --no-daemon || true

# Copy source code and build production jar
COPY src /app/src
RUN gradle bootJar --no-daemon -x test

# Stage 2: Runtime Container
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Create non-root user for security
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel
USER sentinel:sentinel

# Copy compiled jar from build stage
COPY --from=build /app/build/libs/*.jar app.jar

EXPOSE 8080

ENV PORT=8080
ENV SPRING_DATA_MONGODB_URI=mongodb://mongodb:27017/sentinelcore

ENTRYPOINT ["java", "-jar", "app.jar"]
