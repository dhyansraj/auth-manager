# Build context MUST be the repo root, not apps/auth-manager/:
#   docker build -f apps/auth-manager/Dockerfile -t auth-manager:tag .

# ───── Stage 1: build ─────
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src

# Copy the whole reactor so libs/auth-lib resolves.
# All declared modules need their pom.xml present even if we don't build them
# (Maven validates the parent's <modules> list during reactor parsing).
COPY pom.xml ./
COPY libs/auth-lib/pom.xml ./libs/auth-lib/
COPY apps/auth-manager/pom.xml ./apps/auth-manager/
COPY apps/auth-client-sample/pom.xml ./apps/auth-client-sample/

# Warm the dep cache (best-effort; ignores failures from missing src)
RUN mvn -B -f apps/auth-manager/pom.xml dependency:go-offline -DexcludeArtifactIds=auth-lib || true

# Now copy sources
COPY libs/auth-lib/src ./libs/auth-lib/src
COPY apps/auth-manager/src ./apps/auth-manager/src

# Build the fat jar
RUN mvn -B -pl apps/auth-manager -am clean package -DskipTests

# ───── Stage 2: runtime ─────
FROM eclipse-temurin:21-jre-alpine AS runtime
WORKDIR /app
COPY --from=build /src/apps/auth-manager/target/auth-manager-0.1.0-SNAPSHOT.jar app.jar

# Spring Boot's "graceful" shutdown
ENV SPRING_LIFECYCLE_TIMEOUT_PER_SHUTDOWN_PHASE=30s
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError"

# Non-root
RUN addgroup -g 1000 app && adduser -D -u 1000 -G app app
USER app

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
