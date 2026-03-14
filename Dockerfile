# Use official PHP image with Apache
FROM php:8.2-apache

# Copy project files into Apache's web root
COPY . /var/www/html/

# Enable Apache rewrite module (if needed)
RUN docker-php-ext-install mysqli pdo pdo_mysql
RUN a2enmod rewrite

# Expose port 80
EXPOSE 80
