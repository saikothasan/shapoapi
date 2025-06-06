-- This seed file populates the database with an admin user and sample products.
-- Run this with `npm run db:seed`
-- The admin password is 'password123'. The application will hash it on login.
-- IMPORTANT: You should manually create and hash a new password for your production admin user.

-- Delete existing data to prevent conflicts on re-seeding
DELETE FROM OrderItems;
DELETE FROM Orders;
DELETE FROM Products;
DELETE FROM Users;

-- Create Admin User
-- The password 'password123' will be hashed by the application upon first login.
-- This hash is just a placeholder and will not match.
INSERT INTO Users (id, email, name, password, role) VALUES
('a1b2c3d4-e5f6-7890-1234-567890abcdef', 'admin@example.com', 'Admin User', 'placeholder-hash-will-be-overwritten-on-login', 'ADMIN');

-- Create Sample Products
INSERT INTO Products (id, name, description, price, stock, imageUrl) VALUES
('prod_1', 'Modern Wireless Mouse', 'A sleek, ergonomic wireless mouse with long battery life and silent clicks. Perfect for any workspace.', 29.99, 150, 'https://placehold.co/600x400/3498db/ffffff?text=Mouse'),
('prod_2', 'Mechanical Keyboard', 'RGB backlit mechanical keyboard with blue switches for a tactile and clicky typing experience. Fully programmable.', 89.99, 75, 'https://placehold.co/600x400/2ecc71/ffffff?text=Keyboard'),
('prod_3', '4K Ultra HD Monitor', '27-inch 4K UHD monitor with HDR support and a slim bezel design. Delivers stunning visuals for work and play.', 349.50, 40, 'https://placehold.co/600x400/9b59b6/ffffff?text=Monitor'),
('prod_4', 'USB-C Hub', '7-in-1 USB-C hub with HDMI, SD card reader, 3x USB 3.0 ports, and 100W power delivery. A must-have for modern laptops.', 39.99, 200, 'https://placehold.co/600x400/f1c40f/ffffff?text=Hub'),
('prod_5', 'Noise-Cancelling Headphones', 'Over-ear Bluetooth headphones with active noise cancellation and up to 30 hours of playback.', 199.00, 60, 'https://placehold.co/600x400/e74c3c/ffffff?text=Headphones'),
('prod_6', 'Webcam Pro', '1080p HD webcam with a built-in ring light and stereo microphones for professional-quality video calls.', 69.99, 110, 'https://placehold.co/600x400/1abc9c/ffffff?text=Webcam');
