DROP DATABASE IF EXISTS web;
CREATE DATABASE web CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE web;

-- Core Tables
CREATE TABLE users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    phone VARCHAR(20),
    user_type ENUM('customer', 'admin') DEFAULT 'customer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    remember_token VARCHAR(100) NULL,
    remember_token_expires_at TIMESTAMP NULL
);

ALTER TABLE users 
ADD COLUMN is_active BOOLEAN DEFAULT TRUE;

CREATE TABLE password_reset_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    token VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE cities (
    city_id INT PRIMARY KEY AUTO_INCREMENT,
    city_name VARCHAR(100) NOT NULL UNIQUE,
    country VARCHAR(100) DEFAULT 'United Kingdom'
);

-- Hotel Related Tables
CREATE TABLE hotels (
    hotel_id INT PRIMARY KEY AUTO_INCREMENT,
    city_id INT NOT NULL,
    hotel_name VARCHAR(100) NOT NULL,
    description TEXT,
    address TEXT NOT NULL,
    total_rooms INT NOT NULL,
    star_rating INT,
    main_image VARCHAR(255),
    features TEXT,
    check_in_time TIME DEFAULT '14:00:00',
    check_out_time TIME DEFAULT '11:00:00',
    FOREIGN KEY (city_id) REFERENCES cities(city_id)
);

CREATE TABLE room_types (
    room_type_id INT PRIMARY KEY AUTO_INCREMENT,
    type_name VARCHAR(50) NOT NULL,
    max_guests INT NOT NULL,
    price_multiplier DECIMAL(4,2) NOT NULL,
    description TEXT,
    room_size VARCHAR(50)
);
CREATE TABLE rooms (
    room_id INT PRIMARY KEY AUTO_INCREMENT,
    hotel_id INT NOT NULL,
    room_type_id INT NOT NULL,
    room_number VARCHAR(10) NOT NULL,
    description TEXT,
    main_image VARCHAR(255),
    base_price_peak DECIMAL(10,2) NOT NULL,
    base_price_offpeak DECIMAL(10,2) NOT NULL,
    features TEXT,
    floor_number INT,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (hotel_id) REFERENCES hotels(hotel_id),
    FOREIGN KEY (room_type_id) REFERENCES room_types(room_type_id),
    UNIQUE KEY unique_room_hotel (hotel_id, room_number)
);

-- Features and Amenities
CREATE TABLE room_features (
    feature_id INT PRIMARY KEY AUTO_INCREMENT,
    feature_name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    additional_cost DECIMAL(10,2) DEFAULT 0.00,
    icon_class VARCHAR(50)
);

CREATE TABLE room_feature_mapping (
    room_id INT NOT NULL,
    feature_id INT NOT NULL,
    PRIMARY KEY (room_id, feature_id),
    FOREIGN KEY (room_id) REFERENCES rooms(room_id),
    FOREIGN KEY (feature_id) REFERENCES room_features(feature_id)
);

-- Seasonal and Pricing Tables
CREATE TABLE seasons (
    season_id INT PRIMARY KEY AUTO_INCREMENT,
    season_name VARCHAR(50) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    is_peak BOOLEAN DEFAULT FALSE,
    year INT NOT NULL,
    price_multiplier DECIMAL(4,2) DEFAULT 1.00,
    UNIQUE KEY unique_season_period (start_date, end_date, year)
);

CREATE TABLE currencies (
    currency_id INT PRIMARY KEY AUTO_INCREMENT,
    currency_code CHAR(3) NOT NULL UNIQUE,
    currency_name VARCHAR(50) NOT NULL,
    symbol VARCHAR(5),
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE exchange_rates (
    rate_id INT PRIMARY KEY AUTO_INCREMENT,
    from_currency CHAR(3) NOT NULL,
    to_currency CHAR(3) NOT NULL,
    rate DECIMAL(10,5) NOT NULL,
    effective_date DATE NOT NULL,
    UNIQUE KEY unique_daily_rate (from_currency, to_currency, effective_date)
);

-- Booking Related Tables
CREATE TABLE bookings (
    booking_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    room_id INT NOT NULL,
    check_in_date DATE NOT NULL,
    check_out_date DATE NOT NULL,
    num_guests INT NOT NULL,
    total_price DECIMAL(10,2) NOT NULL,
    original_price DECIMAL(10,2),
    advance_booking_discount DECIMAL(10,2) DEFAULT 0.00,
    cancellation_charge DECIMAL(10,2) DEFAULT 0.00,
    booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    cancellation_date TIMESTAMP NULL,
    status ENUM('confirmed', 'cancelled', 'completed') DEFAULT 'confirmed',
    payment_status ENUM('pending', 'paid', 'refunded') DEFAULT 'pending',
    payment_date TIMESTAMP NULL,
    currency VARCHAR(10) DEFAULT 'GBP',
    exchange_rate DECIMAL(10,5) DEFAULT 1.0,
    special_requests TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (room_id) REFERENCES rooms(room_id)
);

ALTER TABLE bookings 
ADD COLUMN applied_discount DECIMAL(10,2) DEFAULT 0.00;

ALTER TABLE bookings 
ADD COLUMN guest_name VARCHAR(255),
ADD COLUMN guest_email VARCHAR(255),
ADD COLUMN guest_phone VARCHAR(50);

CREATE TABLE room_inventory (
    inventory_id INT PRIMARY KEY AUTO_INCREMENT,
    hotel_id INT NOT NULL,
    room_type_id INT NOT NULL,
    total_rooms INT NOT NULL,
    available_rooms INT NOT NULL,
    date DATE NOT NULL,
    FOREIGN KEY (hotel_id) REFERENCES hotels(hotel_id),
    FOREIGN KEY (room_type_id) REFERENCES room_types(room_type_id),
    UNIQUE KEY unique_daily_inventory (hotel_id, room_type_id, date)
);



-- Reviews and Ratings
CREATE TABLE reviews (
    review_id INT PRIMARY KEY AUTO_INCREMENT,
    booking_id INT NOT NULL,
    user_id INT NOT NULL,
    hotel_id INT NOT NULL,
    rating INT NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment TEXT,
    review_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_verified BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (booking_id) REFERENCES bookings(booking_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (hotel_id) REFERENCES hotels(hotel_id)
);

CREATE TABLE newsletter_subscribers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_email (email)
);

select * from newsletter_subscribers;

-- faqs table
CREATE TABLE faqs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    category VARCHAR(50),
    display_order INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    submitted_by INT,
    is_approved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (submitted_by) REFERENCES users(user_id)
);

-- Create table for user FAQ suggestions
CREATE TABLE faq_suggestions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    question TEXT NOT NULL,
    user_id INT,
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);


-- Indexes for performance optimization
CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_user_type ON users(user_type);
CREATE INDEX idx_hotel_city ON hotels(city_id);
CREATE INDEX idx_hotel_name ON hotels(hotel_name);
CREATE INDEX idx_hotel_rating ON hotels(star_rating);
CREATE INDEX idx_room_hotel ON rooms(hotel_id);
CREATE INDEX idx_room_type ON rooms(room_type_id);
CREATE INDEX idx_room_price_peak ON rooms(base_price_peak);
CREATE INDEX idx_room_price_offpeak ON rooms(base_price_offpeak);
CREATE INDEX idx_booking_user ON bookings(user_id);
CREATE INDEX idx_booking_room ON bookings(room_id);
CREATE INDEX idx_booking_dates ON bookings(check_in_date, check_out_date);
CREATE INDEX idx_booking_status ON bookings(status);
CREATE INDEX idx_booking_date ON bookings(booking_date);
CREATE INDEX idx_season_dates ON seasons(start_date, end_date);
CREATE INDEX idx_exchange_rate_date ON exchange_rates(effective_date);
CREATE INDEX idx_room_inventory_date ON room_inventory(date);

CREATE INDEX idx_rooms_active ON rooms(is_active);
CREATE INDEX idx_reviews_hotel_rating ON reviews(hotel_id, rating);
CREATE INDEX idx_bookings_status_dates ON bookings(status, check_in_date, check_out_date);

CREATE INDEX idx_faq_active ON faqs(is_active);
CREATE INDEX idx_faq_approved ON faqs(is_approved);
CREATE INDEX idx_faq_suggestions_status ON faq_suggestions(status);


-- Insert initial data
INSERT INTO users (email, password_hash, first_name, last_name, phone, user_type) VALUES
('admin@worldhotels.com', 'scrypt:32768:8:1$fxxT4EHYUvLidnsY$f0dbb1933b639bf926941d02e7228685e42d2100c62fc8c6f6d732cba60c58e053d471d58a78fbb6f3d76f2b6479974effd790850d8f0959e113bd8ff9a4064c', 'Admin', 'User', '1234567890', 'admin'),
('john@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4WAhOHqMfy', 'John', 'Doe', '2345678901', 'customer'),
('jane@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4WAhOHqMfy', 'Jane', 'Smith', '3456789012', 'customer');

INSERT INTO cities (city_name) VALUES
('London'),
('Manchester'),
('Birmingham'),
('Edinburgh'),
('Aberdeen'),
('Belfast'),
('Bristol'),
('Cardiff'),
('Glasgow'),
('Newcastle'),
('Norwich'),
('Nottingham'),
('Oxford'),
('Plymouth'),
('Swansea'),
('Bournemouth'),
('Kent');


-- Room types
INSERT INTO room_types (type_name, max_guests, price_multiplier) VALUES
('Standard', 1, 1.00),
('Double', 2, 1.20),
('Family', 4, 1.50);

-- Add new sample data for features
INSERT INTO room_features (feature_name, description, additional_cost, icon_class) VALUES
('WiFi', 'High-speed wireless internet', 0.00, 'fas fa-wifi'),
('Mini-bar', 'Fully stocked mini-bar', 15.00, 'fas fa-glass-martini'),
('TV', 'Flat-screen TV with cable channels', 0.00, 'fas fa-tv'),
('Breakfast', 'Continental breakfast', 20.00, 'fas fa-coffee'),
('Air Conditioning', 'Climate control', 0.00, 'fas fa-snowflake'),
('Safe', 'In-room safe', 5.00, 'fas fa-lock');

INSERT INTO currencies (currency_code, currency_name, symbol, is_active) VALUES
('GBP', 'British Pound', '£', TRUE),
('USD', 'US Dollar', '$', TRUE),
('EUR', 'Euro', '€', TRUE),
('AUD', 'Australian Dollar', 'A$', TRUE);

INSERT INTO seasons (season_name, start_date, end_date, is_peak, year, price_multiplier) VALUES
('Spring Peak', '2024-04-01', '2024-04-30', TRUE, 2024, 1.5),
('Summer Peak', '2024-05-01', '2024-08-31', TRUE, 2024, 1.8),
('Autumn Off-Peak', '2024-09-01', '2024-10-31', FALSE, 2024, 1.0),
('Winter Peak', '2024-11-01', '2024-12-31', TRUE, 2024, 1.3);


ALTER TABLE bookings 
ADD COLUMN special_request_status VARCHAR(20) DEFAULT 'pending',
ADD COLUMN special_request_notes TEXT,
ADD COLUMN special_request_handled_at DATETIME;

select* FROM BOOKINGS;

-- Hotels
INSERT INTO hotels (city_id, hotel_name, description, address, total_rooms, star_rating, main_image, features) VALUES
(1, 'Elite World', 'Luxurious suites, spa and wellness center, gourmet dining, private concierge, and state-of-the-art fitness facilities.', 'LONDON, UK', 160, 7, 'hotel2.jpg', 'WiFi, Pool, Gym, Restaurant'),
(2, 'WorldLux Hotel', 'Panoramic city views, rooftop pool, 24/7 room service, fine dining restaurants, and high-speed Wi-Fi.', 'MANCHESTER, UK', 150, 7, 'worldluxhotel.jpg', 'WiFi, Restaurant, Business Center'),
(3, 'Infinity World Suites', 'Private suites, private infinity pools, gourmet restaurants, wellness retreats, high-end amenities, and 24/7 concierge services.', 'Birmingham, UK', 110, 7, 'infinityworld.jpg', 'WiFi, Restaurant,Bar'),
(4, 'Royal Globe Hotels', 'Royal suites with private balconies, spa and wellness center, 24-hour butler service, luxurious lounges, and a full-service business center.', 'New Castle, UK', 120, 5, 'royalglobe.jpg', 'WiFi, Spa, Restaurant'),
(5, 'Exquisite World Inns', 'Spacious rooms, infinity pools, luxury spas, fine dining, personalized concierge, and exclusive event spaces.','Gasglow, UK', 140, 7, 'exquisticworldinss.jpg', 'WiFi, Gym'),
(6, 'Grand Horizon', 'Sky-high views, gourmet dining options, fitness center, expansive meeting rooms, and exclusive VIP lounges.','Kent, UK', 140, 7, 'exquisticworldinss.jpg', 'WiFi, Gym'),
(7, 'Imperial Havens', 'Luxurious havens, private balconies, gourmet dining, exclusive lounges,stylish rooms, rooftop bar, and a refined ambiance.','Bristol, UK', 100, 7, 'grandhorizon.jpg', 'WiFi, Gym, TV'),
(8, 'Serene Suites', 'Unparalleled service, sumptuous suites, exclusive club lounge, and a lavish setting.','Aberdeen, UK', 90, 7, 'serene.jpg', 'WiFi, Gym, Pool , Bar'),
(9, 'Classic Oasis', 'Impeccable service, opulent rooms, lavish spa, private chauffeurs, in-room massages and a luxurious setting.','Belfast, UK', 80, 7, 'classic.jpeg', 'WiFi, Gym, TV, POOL, Bar, Cafe');

-- Room types
INSERT INTO room_types (type_name, max_guests, price_multiplier) VALUES
('Standard', 1, 1.00),
('Double', 2, 1.20),
('Family', 4, 1.50);

-- Rooms (adding 5 rooms for each hotel)
INSERT INTO rooms (hotel_id, room_type_id, room_number, description, main_image, base_price_peak, base_price_offpeak, features) VALUES
-- London Hotel
(1, 1, '101', 'Cozy standard room', 'london_std.jpg', 200, 100, 'TV, WiFi, Coffee Maker'),
(1, 2, '102', 'Spacious double room', 'london_dbl.jpg', 240, 120, 'TV, WiFi, Mini Bar'),
(1, 3, '103', 'Large family room', 'london_fam.jpg', 300, 150, 'TV, WiFi, Kitchen'),
(1, 1, '104', 'Standard room with view', 'london_std_view.jpg', 200, 100, 'TV, WiFi, City View'),
(1, 2, '105', 'Double room with view', 'london_dbl_view.jpg', 240, 120, 'TV, WiFi, City View'),

-- Manchester Hotel
(2, 1, '201', 'Modern standard room', 'man_std.jpg', 180, 90, 'TV, WiFi'),
(2, 2, '202', 'Modern double room', 'man_dbl.jpg', 216, 108, 'TV, WiFi, Mini Bar'),
(2, 3, '203', 'Modern family suite', 'man_fam.jpg', 270, 135, 'TV, WiFi, Kitchen'),
(2, 1, '204', 'Standard city view', 'man_std_view.jpg', 180, 90, 'TV, WiFi, View'),
(2, 2, '205', 'Double city view', 'man_dbl_view.jpg', 216, 108, 'TV, WiFi, View'),

-- Birmingham Hotel
(3, 1, '201', 'Modern standard room', 'man_std.jpg', 180, 90, 'TV, WiFi'),
(3, 2, '202', 'Modern double room', 'man_dbl.jpg', 216, 108, 'TV, WiFi, Mini Bar'),
(3, 3, '203', 'Modern family suite', 'man_fam.jpg', 270, 135, 'TV, WiFi, Kitchen'),
(3, 1, '204', 'Standard city view', 'man_std_view.jpg', 180, 90, 'TV, WiFi, View'),
(3, 2, '205', 'Double city view', 'man_dbl_view.jpg', 216, 108, 'TV, WiFi, View'),

-- New Castle Hotel
(4, 1, '201', 'Modern standard room', 'man_std.jpg', 180, 90, 'TV, WiFi'),
(4, 2, '202', 'Modern double room', 'man_dbl.jpg', 216, 108, 'TV, WiFi, Mini Bar'),
(4, 3, '203', 'Modern family suite', 'man_fam.jpg', 270, 135, 'TV, WiFi, Kitchen'),
(4, 1, '204', 'Standard city view', 'man_std_view.jpg', 180, 90, 'TV, WiFi, View'),
(4, 2, '205', 'Double city view', 'man_dbl_view.jpg', 216, 108, 'TV, WiFi, View'),

-- Gasglow Hotel
(5, 1, '201', 'Modern standard room', 'man_std.jpg', 180, 90, 'TV, WiFi'),
(5, 2, '202', 'Modern double room', 'man_dbl.jpg', 216, 108, 'TV, WiFi, Mini Bar'),
(5, 3, '203', 'Modern family suite', 'man_fam.jpg', 270, 135, 'TV, WiFi, Kitchen'),
(5, 1, '204', 'Standard city view', 'man_std_view.jpg', 180, 90, 'TV, WiFi, View'),
(5, 2, '205', 'Double city view', 'man_dbl_view.jpg', 216, 108, 'TV, WiFi, View'),

-- kent Hotel
(6, 1, '201', 'Modern standard room', 'man_std.jpg', 180, 90, 'TV, WiFi'),
(6, 2, '202', 'Modern double room', 'man_dbl.jpg', 216, 108, 'TV, WiFi, Mini Bar'),
(6, 3, '203', 'Modern family suite', 'man_fam.jpg', 270, 135, 'TV, WiFi, Kitchen'),
(6, 1, '204', 'Standard city view', 'man_std_view.jpg', 180, 90, 'TV, WiFi, View'),
(6, 2, '205', 'Double city view', 'man_dbl_view.jpg', 216, 108, 'TV, WiFi, View'),

-- Bristol Hotel
(7, 1, '201', 'Modern standard room', 'man_std.jpg', 180, 90, 'TV, WiFi'),
(7, 2, '202', 'Modern double room', 'man_dbl.jpg', 216, 108, 'TV, WiFi, Mini Bar'),
(7, 3, '203', 'Modern family suite', 'man_fam.jpg', 270, 135, 'TV, WiFi, Kitchen'),
(7, 1, '204', 'Standard city view', 'man_std_view.jpg', 180, 90, 'TV, WiFi, View'),
(7, 2, '205', 'Double city view', 'man_dbl_view.jpg', 216, 108, 'TV, WiFi, View'),

-- Aberdeen Hotel
(8, 1, '201', 'Modern standard room', 'man_std.jpg', 180, 90, 'TV, WiFi'),
(8, 2, '202', 'Modern double room', 'man_dbl.jpg', 216, 108, 'TV, WiFi, Mini Bar'),
(8, 3, '203', 'Modern family suite', 'man_fam.jpg', 270, 135, 'TV, WiFi, Kitchen'),
(8, 1, '204', 'Standard city view', 'man_std_view.jpg', 180, 90, 'TV, WiFi, View'),
(8, 2, '205', 'Double city view', 'man_dbl_view.jpg', 216, 108, 'TV, WiFi, View'),

-- Belfast Hotel
(9, 1, '201', 'Modern standard room', 'man_std.jpg', 180, 90, 'TV, WiFi'),
(9, 2, '202', 'Modern double room', 'man_dbl.jpg', 216, 108, 'TV, WiFi, Mini Bar'),
(9, 3, '203', 'Modern family suite', 'man_fam.jpg', 270, 135, 'TV, WiFi, Kitchen'),
(9, 1, '204', 'Standard city view', 'man_std_view.jpg', 180, 90, 'TV, WiFi, View'),
(9, 2, '205', 'Double city view', 'man_dbl_view.jpg', 216, 108, 'TV, WiFi, View');

ALTER TABLE rooms ADD COLUMN status VARCHAR(20) DEFAULT 'available';
