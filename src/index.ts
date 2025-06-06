import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { jwt, sign, verify } from 'hono/jwt';
import { PrismaClient } from '@prisma/client';
import { PrismaD1 } from '@prisma/adapter-d1';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';

// Define the shape of the environment variables and bindings
export interface Env {
  DB: D1Database;
  JWT_SECRET: string;
}

// --- Hashing Utility (using Web Crypto API) ---
const subtle = crypto.subtle;
const encoder = new TextEncoder();

async function hashPassword(password: string): Promise<string> {
    const data = encoder.encode(password);
    const hashBuffer = await subtle.digest('SHA-256', data);
    // Convert ArrayBuffer to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}


// --- Zod Schemas for Validation ---
const registerSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(8),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

const createProductSchema = z.object({
    name: z.string().min(3),
    description: z.string().optional(),
    price: z.number().positive(),
    stock: z.number().int().min(0),
    imageUrl: z.string().url().optional(),
});

const createOrderSchema = z.object({
    items: z.array(z.object({
        productId: z.string(),
        quantity: z.number().int().positive(),
    })).min(1),
});


// Initialize the Hono app with types for bindings
const app = new Hono<{ Bindings: Env }>();

// --- Middleware ---

// CORS for all routes
app.use('*', cors());

// Initialize Prisma Client with D1 adapter
app.use('*', async (c, next) => {
  const adapter = new PrismaD1(c.env.DB);
  const prisma = new PrismaClient({ adapter });
  c.set('prisma', prisma);
  await next();
});

// Authentication Middleware
const authMiddleware = async (c, next) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized: Missing or invalid token' }, 401);
  }
  const token = authHeader.split(' ')[1];
  try {
    const decodedPayload = await verify(token, c.env.JWT_SECRET);
    c.set('jwtPayload', decodedPayload);
    await next();
  } catch (err) {
    return c.json({ error: 'Unauthorized: Invalid token' }, 401);
  }
};

// Admin-only Middleware
const adminMiddleware = async (c, next) => {
    const payload = c.get('jwtPayload');
    if(payload.role !== 'ADMIN') {
        return c.json({ error: 'Forbidden: Admin access required' }, 403);
    }
    await next();
};


// --- Public Routes (No Auth Required) ---

// Health check
app.get('/', (c) => c.json({ message: 'E-commerce API is running!' }));

// User Registration
app.post('/auth/register', zValidator('json', registerSchema), async (c) => {
  const prisma = c.get('prisma');
  const { name, email, password } = c.req.valid('json');

  const hashedPassword = await hashPassword(password);

  try {
    const newUser = await prisma.user.create({
      data: {
        id: crypto.randomUUID(),
        name,
        email,
        password: hashedPassword,
        role: 'USER', // Default role
      },
    });
    return c.json({ id: newUser.id, email: newUser.email }, 201);
  } catch (e) {
    console.error(e);
    return c.json({ error: 'User with this email already exists' }, 409);
  }
});

// User Login
app.post('/auth/login', zValidator('json', loginSchema), async (c) => {
    const prisma = c.get('prisma');
    const { email, password } = c.req.valid('json');
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
        return c.json({ error: 'Invalid credentials' }, 401);
    }

    const hashedPassword = await hashPassword(password);
    if (user.password !== hashedPassword) {
        return c.json({ error: 'Invalid credentials' }, 401);
    }

    const payload = {
        sub: user.id,
        role: user.role,
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24) // 24 hours
    };
    const token = await sign(payload, c.env.JWT_SECRET);
    return c.json({ token });
});

// Get all products
app.get('/api/products', async (c) => {
    const prisma = c.get('prisma');
    const products = await prisma.product.findMany({
        where: { stock: { gt: 0 } },
        orderBy: { createdAt: 'desc' }
    });
    return c.json(products);
});

// Get a single product by ID
app.get('/api/products/:id', async (c) => {
    const prisma = c.get('prisma');
    const id = c.req.param('id');
    const product = await prisma.product.findUnique({ where: { id } });
    if (!product) {
        return c.json({ error: 'Product not found' }, 404);
    }
    return c.json(product);
});

// --- Protected Routes (Auth Required) ---

// Get current user's profile
app.get('/api/users/me', authMiddleware, async (c) => {
    const prisma = c.get('prisma');
    const payload = c.get('jwtPayload');
    const user = await prisma.user.findUnique({
        where: { id: payload.sub },
        select: { id: true, name: true, email: true, role: true, createdAt: true }
    });
     if (!user) {
        return c.json({ error: 'User not found' }, 404);
    }
    return c.json(user);
});


// Create a new order
app.post('/api/orders', authMiddleware, zValidator('json', createOrderSchema), async (c) => {
    const prisma = c.get('prisma');
    const payload = c.get('jwtPayload');
    const { items } = c.req.valid('json');
    const userId = payload.sub;

    try {
        const order = await prisma.$transaction(async (tx) => {
            let total = 0;
            const orderItemsData = [];
            
            for (const item of items) {
                const product = await tx.product.findUnique({ where: { id: item.productId } });
                if (!product || product.stock < item.quantity) {
                    throw new Error(`Product ${item.productId} is out of stock or does not exist.`);
                }

                // Decrease stock
                await tx.product.update({
                    where: { id: item.productId },
                    data: { stock: { decrement: item.quantity } },
                });
                
                total += product.price * item.quantity;
                orderItemsData.push({
                    id: crypto.randomUUID(),
                    productId: product.id,
                    quantity: item.quantity,
                    priceAtPurchase: product.price,
                });
            }

            const newOrder = await tx.order.create({
                data: {
                    id: crypto.randomUUID(),
                    userId,
                    total,
                    items: {
                        create: orderItemsData,
                    },
                },
                include: { items: { include: { product: true } } },
            });

            return newOrder;
        });

        return c.json(order, 201);
    } catch (e: any) {
        return c.json({ error: e.message }, 400);
    }
});


// Get user's own orders
app.get('/api/orders', authMiddleware, async (c) => {
    const prisma = c.get('prisma');
    const payload = c.get('jwtPayload');
    const orders = await prisma.order.findMany({
        where: { userId: payload.sub },
        include: { items: { include: { product: { select: { name: true, imageUrl: true } } } } },
        orderBy: { createdAt: 'desc' }
    });
    return c.json(orders);
});


// --- Admin Routes ---
const adminRoutes = new Hono();
adminRoutes.use('*', authMiddleware, adminMiddleware);

// Create a new product (Admin only)
adminRoutes.post('/products', zValidator('json', createProductSchema), async (c) => {
    const prisma = c.get('prisma');
    const productData = c.req.valid('json');
    const newProduct = await prisma.product.create({
        data: {
            id: crypto.randomUUID(),
            ...productData
        }
    });
    return c.json(newProduct, 201);
});

// Update a product (Admin only)
adminRoutes.put('/products/:id', zValidator('json', createProductSchema.partial()), async (c) => {
    const prisma = c.get('prisma');
    const id = c.req.param('id');
    const productData = c.req.valid('json');

    try {
        const updatedProduct = await prisma.product.update({
            where: { id },
            data: productData,
        });
        return c.json(updatedProduct);
    } catch (e) {
        return c.json({ error: "Product not found" }, 404);
    }
});

// Delete a product (Admin only)
adminRoutes.delete('/products/:id', async (c) => {
    const prisma = c.get('prisma');
    const id = c.req.param('id');
    try {
        await prisma.product.delete({ where: { id }});
        return new Response(null, { status: 204 });
    } catch(e) {
        return c.json({ error: 'Product not found or cannot be deleted' }, 404);
    }
});


// Register admin routes
app.route('/api/admin', adminRoutes);


// --- Error Handling ---
app.onError((err, c) => {
  console.error(`${err}`);
  return c.json({ error: 'Internal Server Error' }, 500);
});

export default app;
