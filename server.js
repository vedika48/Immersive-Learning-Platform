// server.js - Express server with MongoDB and Google authentication
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

const app = express();

// Initialize Google OAuth client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/immersivelearning', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema and Model
const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String }, // Password is optional for social logins
    googleId: { type: String }, // Google ID for Google authentication
    picture: { type: String }, // Profile picture URL
    interests: { type: String },
    authProvider: { type: String, default: 'local' }, // 'local', 'google', etc.
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Regular Email/Password Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        // Find user by email
        const user = await User.findOne({ email });
        
        // Check if user exists
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Check if this is a social login account
        if (user.authProvider !== 'local') {
            return res.status(400).json({ 
                message: `This account uses ${user.authProvider} authentication. Please sign in with ${user.authProvider}.` 
            });
        }

        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Create JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET || 'your_jwt_secret',
            { expiresIn: '1d' }
        );

        // Send response with token and user info (excluding password)
        const userResponse = {
            _id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            picture: user.picture,
            interests: user.interests,
            authProvider: user.authProvider
        };

        res.json({ token, user: userResponse });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Google Authentication
app.post('/api/auth/google', async (req, res) => {
    try {
        const { idToken } = req.body;
        
        // Verify the Google ID token
        const ticket = await googleClient.verifyIdToken({
            idToken,
            audience: process.env.GOOGLE_CLIENT_ID
        });
        
        // Get user info from the token
        const payload = ticket.getPayload();
        const { sub: googleId, email, given_name, family_name, picture } = payload;
        
        // Check if user already exists
        let user = await User.findOne({ googleId });
        
        if (!user) {
            // Check if user exists with the same email
            user = await User.findOne({ email });
            
            if (user) {
                // If user exists with email but not googleId, update the user with googleId
                if (user.authProvider === 'local') {
                    // User previously registered with email/password
                    return res.status(400).json({ 
                        message: 'An account with this email already exists. Please log in with your password.' 
                    });
                } else {
                    // Update user with Google ID
                    user.googleId = googleId;
                    await user.save();
                }
            } else {
                // Create new user with Google info
                user = new User({
                    firstName: given_name,
                    lastName: family_name,
                    email,
                    googleId,
                    picture,
                    authProvider: 'google'
                });
                
                await user.save();
            }
        }
        
        // Create JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET || 'your_jwt_secret',
            { expiresIn: '1d' }
        );
        
        // User data to return
        const userResponse = {
            _id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            picture: user.picture,
            interests: user.interests,
            authProvider: 'google'
        };
        
        res.json({ token, user: userResponse });
        
    } catch (error) {
        console.error('Google authentication error:', error);
        res.status(401).json({ message: 'Google authentication failed' });
    }
});

// Registration route
app.post('/api/auth/register', async (req, res) => {
    try {
        const { firstName, lastName, email, password, interests } = req.body;
        
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Create new user
        const user = new User({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            interests,
            authProvider: 'local'
        });
        
        await user.save();
        
        // Create JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET || 'your_jwt_secret',
            { expiresIn: '1d' }
        );
        
        // Send response
        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                _id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                interests: user.interests,
                authProvider: 'local'
            }
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Protected route example
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
        req.userId = decoded.userId;
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Invalid token' });
    }
}

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));