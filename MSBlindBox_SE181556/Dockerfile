# Build stage (sử dụng Maven + JDK 17)
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests

# Run stage (JDK 17 nhẹ)
FROM eclipse-temurin:17-jdk-jammy
WORKDIR /app

# Copy JAR từ build stage
COPY --from=builder /app/target/*.jar app.jar

# Expose port (nhớ sửa đúng cho từng service)
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]