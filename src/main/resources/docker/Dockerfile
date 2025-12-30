# Stage 1: Build with Maven
FROM maven:3.9.6-eclipse-temurin-17 AS builder

# Установите рабочую директорию
WORKDIR /app

# Скопируйте файл зависимостей
COPY pom.xml .

# Загрузите зависимости (это позволит кэшировать зависимости между сборками)
RUN mvn dependency:go-offline -B

# Скопируйте исходный код
COPY src ./src

# Соберите приложение
RUN mvn clean package -DskipTests -B

# Stage 2: Run
FROM eclipse-temurin:17-jdk-alpine

# Установите рабочую директорию
WORKDIR /app

# Скопируйте JAR-файл из предыдущего этапа
COPY --from=builder /app/target/backend-0.0.1-SNAPSHOT.jar app.jar

# Запустите приложение
CMD ["java", "-jar", "app.jar"]