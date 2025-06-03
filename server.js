// Basic Express server for MKcode
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Parser } = require('json2csv');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- Add 'role' to User schema ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
});
const User = mongoose.model('User', userSchema);

// Contact Schema
const contactSchema = new mongoose.Schema({
    name: String,
    email: String,
    subject: String,
    message: String,
    createdAt: { type: Date, default: Date.now },
});
const Contact = mongoose.model('Contact', contactSchema);

// Newsletter Schema
const newsletterSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    subscribedAt: { type: Date, default: Date.now },
});
const Newsletter = mongoose.model('Newsletter', newsletterSchema);

// Password Reset Token Schema
const resetTokenSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    token: { type: String, required: true },
    expires: { type: Date, required: true }
});
const ResetToken = mongoose.model('ResetToken', resetTokenSchema);

// Activity Log Schema
const activityLogSchema = new mongoose.Schema({
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: String,
    target: String,
    details: Object,
    date: { type: Date, default: Date.now }
});
const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// JWT Middleware
function auth(req, res, next) {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token, authorization denied' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token is not valid' });
    }
}

// Register
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        if (!name || !email || !password) return res.status(400).json({ message: 'All fields required' });
        const existing = await User.findOne({ email });
        if (existing) return res.status(400).json({ message: 'User already exists' });
        const hashed = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashed });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, user: { name: user.name, email: user.email } });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Profile
app.get('/api/profile', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Contact Form
app.post('/api/contact', async (req, res) => {
    const { name, email, subject, message } = req.body;
    try {
        if (!name || !email || !subject || !message) return res.status(400).json({ message: 'All fields required' });
        const contact = new Contact({ name, email, subject, message });
        await contact.save();
        res.status(201).json({ message: 'Message sent successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Newsletter Subscription
app.post('/api/newsletter', async (req, res) => {
    const { email } = req.body;
    try {
        if (!email) return res.status(400).json({ message: 'Email required' });
        const exists = await Newsletter.findOne({ email });
        if (exists) return res.status(400).json({ message: 'Already subscribed' });
        const sub = new Newsletter({ email });
        await sub.save();
        res.status(201).json({ message: 'Subscribed successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// --- Password Reset Request ---
app.post('/api/request-reset', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email required' });
    const user = await User.findOne({ email });
    if (!user) return res.status(200).json({ message: 'If the email exists, a reset link will be sent.' });
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 1000 * 60 * 30); // 30 min
    await ResetToken.deleteMany({ userId: user._id });
    await new ResetToken({ userId: user._id, token, expires }).save();
    // --- Email sending stub ---
    // In production, use nodemailer to send the reset link below:
    // `${process.env.FRONTEND_URL}/reset-password.html?token=${token}&id=${user._id}`
    console.log(`Password reset link: http://localhost:3000/reset-password.html?token=${token}&id=${user._id}`);
    res.json({ message: 'If the email exists, a reset link will be sent.' });
});

// --- Password Reset ---
app.post('/api/reset-password', async (req, res) => {
    const { userId, token, password } = req.body;
    if (!userId || !token || !password) return res.status(400).json({ message: 'All fields required' });
    const reset = await ResetToken.findOne({ userId, token, expires: { $gt: new Date() } });
    if (!reset) return res.status(400).json({ message: 'Invalid or expired token' });
    const hashed = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate(userId, { password: hashed });
    await ResetToken.deleteMany({ userId });
    res.json({ message: 'Password reset successful' });
});

// --- User Settings Update ---
app.put('/api/profile', auth, async (req, res) => {
    const { name, email, password } = req.body;
    const update = {};
    if (name) update.name = name;
    if (email) update.email = email;
    if (password) update.password = await bcrypt.hash(password, 10);
    try {
        const user = await User.findByIdAndUpdate(req.user.id, update, { new: true, runValidators: true }).select('-password');
        res.json(user);
    } catch (err) {
        res.status(400).json({ message: 'Update failed' });
    }
});

// --- Admin Endpoints (simple, for demo) ---
function adminAuth(req, res, next) {
    // For demo, treat first user as admin. In production, add a role field to User.
    User.findById(req.user.id).then(user => {
        if (user && user.email === 'admin@mkcode.com') next();
        else res.status(403).json({ message: 'Admin only' });
    });
}

app.get('/api/admin/users', auth, adminAuth, async (req, res) => {
    const users = await User.find().select('-password');
    res.json(users);
});

app.get('/api/admin/messages', auth, adminAuth, async (req, res) => {
    const messages = await Contact.find();
    res.json(messages);
});

app.get('/api/admin/newsletter', auth, adminAuth, async (req, res) => {
    const subs = await Newsletter.find();
    res.json(subs);
});

// --- Promote user to admin ---
app.post('/api/admin/promote', auth, adminAuth, async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ message: 'User ID required' });
    const user = await User.findByIdAndUpdate(userId, { role: 'admin' }, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'User promoted to admin', user });
});

// --- Demote admin to user ---
app.post('/api/admin/demote', auth, adminAuth, async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ message: 'User ID required' });
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.role !== 'admin') return res.status(400).json({ message: 'User is not an admin' });
    if (user._id.toString() === req.user.id) return res.status(400).json({ message: 'Cannot demote yourself' });
    user.role = 'user';
    await user.save();
    res.json({ message: 'User demoted to user', user });
});

// --- Admin reset user password ---
app.post('/api/admin/reset-password', auth, adminAuth, async (req, res) => {
    const { userId, password } = req.body;
    if (!userId || !password) return res.status(400).json({ message: 'User ID and new password required' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.findByIdAndUpdate(userId, { password: hashed });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'Password reset for user' });
});

// --- Admin search users ---
app.get('/api/admin/search-users', auth, adminAuth, async (req, res) => {
    const { q } = req.query;
    if (!q) return res.json([]);
    const regex = new RegExp(q, 'i');
    const users = await User.find({ $or: [ { email: regex }, { name: regex } ] }).select('-password');
    res.json(users);
});

// --- Activity Log helpers ---
async function logAdminAction(adminId, action, target, details) {
    await new ActivityLog({ adminId, action, target, details }).save();
}

// --- Get activity logs ---
app.get('/api/admin/activity-logs', auth, adminAuth, async (req, res) => {
    const logs = await ActivityLog.find().sort({ date: -1 }).limit(200).populate('adminId', 'email name');
    res.json(logs);
});

// --- CSV Export helpers ---
app.get('/api/admin/export/:type', auth, adminAuth, async (req, res) => {
    const { type } = req.params;
    let data = [];
    if (type === 'users') data = await User.find().select('-password');
    else if (type === 'messages') data = await Contact.find();
    else if (type === 'newsletter') data = await Newsletter.find();
    else return res.status(400).json({ message: 'Invalid export type' });
    const parser = new Parser();
    const csv = parser.parse(data.map(d => d.toObject ? d.toObject() : d));
    res.header('Content-Type', 'text/csv');
    res.attachment(`${type}-${Date.now()}.csv`);
    res.send(csv);
});

// Root endpoint
app.get('/', (req, res) => {
    res.send('MKcode Backend API Running');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
