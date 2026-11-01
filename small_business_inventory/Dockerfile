FROM php:8.3-apache

RUN apt-get update && apt-get install -y ca-certificates \
    && docker-php-ext-install mysqli \
    && rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite

COPY . /var/www/html/

RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
