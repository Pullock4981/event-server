require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true
}));

// JWT Setup
const maxAge = 3 * 24 * 60 * 60; // 3 days
const createToken = (id) =>
    jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: maxAge });

// MongoDB
const client = new MongoClient(process.env.MONGO_URI);
let usersCollection;
let eventsCollection;

async function connectDB() {
    await client.connect();
    const db = client.db('eventApp');
    usersCollection = db.collection('users');
    eventsCollection = db.collection('events');
    console.log('Connected to MongoDB');
}
connectDB().catch(console.error);

// Middleware: Auth check
function requireAuth(req, res, next) {
    const token = req.cookies.jwt;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch (err) {
        res.clearCookie('jwt');
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// ==== Auth Routes ====

app.get("/", (req, res) => {
    res.json({ status: 200 });
});

app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, photoURL } = req.body;
    if (!name || !email || !password || !photoURL) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const existing = await usersCollection.findOne({ email });
        if (existing) return res.status(400).json({ error: 'Email already in use.' });

        const hashed = await bcrypt.hash(password, 10);
        const { insertedId } = await usersCollection.insertOne({
            name, email, password: hashed, photoURL
        });

        const token = createToken(insertedId.toString());
        res.cookie('jwt', token, { httpOnly: true, maxAge: maxAge * 1000 });
        res.status(201).json({ message: 'Registered', user: { name, email, photoURL } });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

    try {
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(400).json({ error: 'Invalid credentials.' });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: 'Invalid credentials.' });

        const token = createToken(user._id.toString());
        res.cookie('jwt', token, { httpOnly: true, maxAge: maxAge * 1000 });
        res.status(200).json({ message: 'Logged in', user: { name: user.name, email: user.email, photoURL: user.photoURL } });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('jwt');
    res.status(200).json({ message: 'Logged out' });
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
    try {
        const user = await usersCollection.findOne(
            { _id: new ObjectId(req.userId) },
            { projection: { password: 0 } }
        );
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ user });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

// ==== Event Routes ====

app.get('/api/events', async (req, res) => {
    try {
        const events = await eventsCollection.find().toArray();
        res.status(200).json(events);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch events' });
    }
});

app.post('/api/events', requireAuth, async (req, res) => {
    const {
        title, name, date, time, location, description,
        attendeeCount = 0, joinedUsers = []
    } = req.body;

    if (!title || !name || !date || !time || !location || !description) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const result = await eventsCollection.insertOne({
            title,
            name,
            date,
            time,
            location,
            description,
            attendeeCount,
            joinedUsers,
            createdBy: req.userId
        });
        res.status(201).json({ message: 'Event added', id: result.insertedId });
    } catch (err) {
        res.status(500).json({ error: 'Failed to add event' });
    }
});

app.delete('/api/events/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const event = await eventsCollection.findOne({ _id: new ObjectId(id) });

        if (!event) return res.status(404).json({ error: 'Event not found' });
        if (event.createdBy !== req.userId) return res.status(403).json({ error: 'Not allowed to delete this event' });

        const result = await eventsCollection.deleteOne({ _id: new ObjectId(id) });
        res.status(200).json({ message: 'Event deleted' });
    } catch (err) {
        console.error('Delete error:', err);
        res.status(500).json({ error: 'Failed to delete event' });
    }
});

app.patch('/api/events/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = req.body;

        const event = await eventsCollection.findOne({ _id: new ObjectId(id) });
        if (!event) return res.status(404).json({ error: 'Event not found' });
        if (event.createdBy !== req.userId) return res.status(403).json({ error: 'Not allowed to update this event' });

        const result = await eventsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateData }
        );
        res.status(200).json({ message: 'Event updated', result });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update event' });
    }
});

// ==== Start Server ====

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
