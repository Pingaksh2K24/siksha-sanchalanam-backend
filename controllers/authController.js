import pool from '../config/db.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const folder = req.body.folder || 'general';
    const uploadPath = `uploads/${folder}/`;
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only images and documents allowed'));
    }
  }
});

const registerUser = async (req, res) => {
  try {
    const { 
      full_name, 
      dob, 
      gender_id, 
      address, 
      email, 
      phone, 
      alternate_phone, 
      password, 
      role_id, 
      department_id, 
      status_id, 
      profile_image 
    } = req.body;
    
    if (!full_name || !email || !password) {
      return res.status(400).json({ message: 'Full name, email and password are required' });
    }
    
    const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const result = await pool.query(
      'INSERT INTO users (full_name, dob, gender_id, address, email, phone, alternate_phone, password_hash, role_id, department_id, status_id, profile_image) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id, full_name, dob, gender_id, address, email, phone, alternate_phone, role_id, department_id, status_id, profile_image',
      [full_name, dob, gender_id, address, email, phone, alternate_phone, hashedPassword, role_id, department_id, status_id, profile_image]
    );
    
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id }, 'your-secret-key', { expiresIn: '30d' });
    
    res.status(201).json({
      id: user.id,
      full_name: user.full_name,
      dob: user.dob,
      gender_id: user.gender_id,
      address: user.address,
      email: user.email,
      phone: user.phone,
      alternate_phone: user.alternate_phone,
      role_id: user.role_id,
      department_id: user.department_id,
      status_id: user.status_id,
      profile_image: user.profile_image,
      token
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await pool.query('SELECT id, full_name, email, password_hash, username, is_email_verified, is_phone_verified, role_id, status_id, department_id, is_active FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
      // Increment failed login attempts
      await pool.query('UPDATE users SET failed_login_attempts = COALESCE(failed_login_attempts, 0) + 1 WHERE id = $1', [user.id]);
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    // Reset failed login attempts and update last_login time on successful login
    await pool.query('UPDATE users SET failed_login_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
    
    const token = jwt.sign({ id: user.id }, 'your-secret-key', { expiresIn: '30d' });
    
    // Calculate session expiry (2 hours from now)
    const sessionTimeout = new Date();
    sessionTimeout.setHours(sessionTimeout.getHours() + 2);
    
    res.json({
      id: user.id,
      full_name: user.full_name,
      email: user.email,
      username: user.username,
      is_email_verified: user.is_email_verified,
      is_phone_verified: user.is_phone_verified,
      role_id: user.role_id,
      status_id: user.status_id,
      department_id: user.department_id,
      is_active: user.is_active,
      token,
      expires_at: sessionTimeout.toISOString()
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getAllUserList = async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, 
        u.full_name, 
        u.username, 
        u.dob, 
        u.gender_id, 
        u.address, 
        u.email, 
        u.is_email_verified, 
        u.phone, 
        u.alternate_phone, 
        u.is_phone_verified, 
        u.role_id, 
        r.name as role_name,
        u.department_id, 
        d.name as department_name,
        u.status_id, 
        s.name as status_name,
        u.profile_image, 
        u.is_active, 
        u.account_locked 
      FROM users u 
      LEFT JOIN departments d ON u.department_id = d.id 
      LEFT JOIN roles r ON u.role_id = r.id 
      LEFT JOIN status s ON u.status_id = s.id 
      WHERE u.is_active = true 
      ORDER BY u.id DESC
    `);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getUserDetails = async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'SELECT id, full_name, username, dob, gender_id, address, email, is_email_verified, phone, alternate_phone, is_phone_verified, role_id, department_id, status_id, profile_image, is_active, account_locked FROM users WHERE id = $1', 
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const uploadFile = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }
    
    res.json({
      message: 'File uploaded successfully',
      filename: req.file.filename,
      originalname: req.file.originalname,
      size: req.file.size,
      path: req.file.path,
      folder: req.body.folder || 'general'
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getAllDropdowns = async (req, res) => {
  try {
    const rolesQuery = pool.query('SELECT id, name, is_active FROM roles ORDER BY name');
    const departmentsQuery = pool.query('SELECT id, name, is_active FROM departments ORDER BY name');
    const statusQuery = pool.query('SELECT id, name, is_active FROM status ORDER BY name');
    
    const [roles, departments, status] = await Promise.all([
      rolesQuery,
      departmentsQuery,
      statusQuery
    ]);
    
    res.json({
      roles: roles.rows,
      departments: departments.rows,
      status: status.rows
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query('UPDATE users SET is_active = false, deleted_at = CURRENT_TIMESTAMP WHERE id = $1 AND is_active = true RETURNING id', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found or already deleted' });
    }
    
    res.json({ message: 'User deleted successfully', id: result.rows[0].id });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export { registerUser, loginUser, getAllUserList, getUserDetails, uploadFile, upload, getAllDropdowns, deleteUser };