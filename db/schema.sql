-- This schema defines the tables for a basic e-commerce platform.
-- Run this with `npx wrangler d1 execute <YOUR_DB_NAME> --file=./db/schema.sql`

DROP TABLE IF EXISTS OrderItems;
DROP TABLE IF EXISTS Orders;
DROP TABLE IF EXISTS Products;
DROP TABLE IF EXISTS Users;

-- Users table to store customer and admin information
CREATE TABLE Users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL, -- In a real app, this should be a securely hashed password
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'USER' CHECK(role IN ('USER', 'ADMIN')), -- Role-based access control
    createdAt INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Products table for all items available for sale
CREATE TABLE Products (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0,
    imageUrl TEXT,
    createdAt INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Orders table to track customer orders
CREATE TABLE Orders (
    id TEXT PRIMARY KEY,
    userId TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'PAID', 'SHIPPED', 'DELIVERED', 'CANCELLED')),
    total REAL NOT NULL,
    createdAt INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (userId) REFERENCES Users(id)
);

-- OrderItems table to link products to orders (many-to-many relationship)
CREATE TABLE OrderItems (
    id TEXT PRIMARY KEY,
    orderId TEXT NOT NULL,
    productId TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    priceAtPurchase REAL NOT NULL, -- Price of the product at the time of purchase
    FOREIGN KEY (orderId) REFERENCES Orders(id),
    FOREIGN KEY (productId) REFERENCES Products(id)
);

-- Create indexes for faster lookups on frequently queried columns
CREATE INDEX idx_users_email ON Users(email);
CREATE INDEX idx_orders_user_id ON Orders(userId);
CREATE INDEX idx_orderitems_order_id ON OrderItems(orderId);
CREATE INDEX idx_orderitems_product_id ON OrderItems(productId);

