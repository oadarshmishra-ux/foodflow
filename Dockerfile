FROM php:8.2-apache

# Copy project files into Apache's web root
COPY . /var/www/html/

# Enable Apache rewrite module and PHP extensions
RUN docker-php-ext-install mysqli pdo pdo_mysql
RUN a2enmod rewrite

# Configure Apache to use Railway's PORT
RUN sed -i 's/Listen 80/Listen ${PORT}/' /etc/apache2/ports.conf \
    && sed -i 's/:80/:${PORT}/' /etc/apache2/sites-available/000-default.conf

# Expose the dynamic port
EXPOSE ${PORT}
