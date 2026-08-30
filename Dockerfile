FROM php:8.2-cli-alpine
RUN docker-php-ext-install bcmath
WORKDIR /app
COPY . /app
CMD php -S 0.0.0.0:$PORT -t /app
