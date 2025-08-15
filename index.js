#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Color codes for console output
const colors = {
  green: '\x1b[32m',
  blue: '\x1b[34m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

// Log with colors
const log = {
  success: (msg) => console.log(`${colors.green}✓${colors.reset} ${msg}`),
  info: (msg) => console.log(`${colors.blue}ℹ${colors.reset} ${msg}`),
  warn: (msg) => console.log(`${colors.yellow}⚠${colors.reset} ${msg}`),
  error: (msg) => console.log(`${colors.red}✗${colors.reset} ${msg}`),
  title: (msg) => console.log(`${colors.bold}${colors.blue}${msg}${colors.reset}`)
};

// Get project name from command line arguments
const projectName = process.argv[2];

if (!projectName) {
  log.error('Please provide a project name');
  console.log('Usage: create-node-api <project-name>');
  process.exit(1);
}

// Validate project name
if (!/^[a-zA-Z0-9-_]+$/.test(projectName)) {
  log.error('Project name can only contain letters, numbers, hyphens, and underscores');
  process.exit(1);
}

const projectPath = path.join(process.cwd(), projectName);

// Check if directory already exists
if (fs.existsSync(projectPath)) {
  log.error(`Directory "${projectName}" already exists`);
  process.exit(1);
}

log.title(`🚀 Creating Node.js API Project: ${projectName}`);

// Create project directory structure
const createDirectory = (dirPath) => {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
};

// File templates
const templates = {
  packageJson: {
    "name": projectName,
    "version": "1.0.0",
    "description": "A modern Node.js API with Express and MongoDB",
    "main": "src/app.js",
    "scripts": {
      "start": "node src/app.js",
      "dev": "nodemon src/app.js",
      "test": "echo \"Error: no test specified\" && exit 1"
    },
    "keywords": ["nodejs", "express", "mongodb", "api", "rest"],
    "author": "",
    "license": "MIT",
    "dependencies": {
      "express": "^4.18.2",
      "mongoose": "^7.5.0",
      "bcryptjs": "^2.4.3",
      "jsonwebtoken": "^9.0.2",
      "cookie-parser": "^1.4.6",
      "dotenv": "^16.3.1",
      "helmet": "^7.0.0",
      "cors": "^2.8.5"
    },
    "devDependencies": {
      "nodemon": "^3.0.1"
    }
  },

  gitignore: `# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/

# nyc test coverage
.nyc_output

# Logs
logs
*.log

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# IDE
.vscode/
.idea/
*.swp
*.swo

# Build directories
dist/
build/
`,

  envTemplate: `# Server Configuration
PORT=3000
NODE_ENV=development

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/${projectName}

# Security Configuration
JWT_SECRET=your-secret-key-change-this-in-production
JWT_EXPIRES_IN=7d
JWT_COOKIE_EXPIRES=7

# CORS Configuration
CORS_ORIGIN=http://localhost:3000
`,

  appJs: `const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const authRoutes = require('./routes/authRoutes');
const globalErrorHandler = require('./middleware/error');
const ApiError = require('./utils/apiError');

const app = express();

// Security middleware
app.use(helmet());

// CORS configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true
}));

// Body parsing middleware
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// API Routes
app.use('/api/v1/auth', authRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'API is running smoothly',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV
  });
});

// Handle undefined routes
app.all('*', (req, res, next) => {
  next(new ApiError(\`Route \${req.originalUrl} not found on this server\`, 404));
});

// Global error handling middleware
app.use(globalErrorHandler);

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('✓ Database connection established');
  })
  .catch((error) => {
    console.error('✗ Database connection failed:', error.message);
    process.exit(1);
  });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(\`🚀 Server running on port \${PORT} in \${process.env.NODE_ENV} mode\`);
});

module.exports = app;
`,

  dbConfig: `const mongoose = require('mongoose');

const connectDatabase = async () => {
  try {
    const connection = await mongoose.connect(process.env.MONGODB_URI);
    console.log(\`Database connected: \${connection.connection.host}\`);
    return connection;
  } catch (error) {
    console.error('Database connection error:', error.message);
    throw error;
  }
};

// Graceful shutdown
process.on('SIGINT', async () => {
  try {
    await mongoose.connection.close();
    console.log('Database connection closed');
    process.exit(0);
  } catch (error) {
    console.error('Error closing database connection:', error);
    process.exit(1);
  }
});

module.exports = connectDatabase;
`,

  jwtConfig: `const jwt = require('jsonwebtoken');

const generateToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  });
};

const verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};

const sendTokenResponse = (user, statusCode, res, message = 'Success') => {
  const token = generateToken({ id: user._id, email: user.email });
  
  const cookieOptions = {
    expires: new Date(
      Date.now() + (process.env.JWT_COOKIE_EXPIRES || 7) * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  };

  res.cookie('token', token, cookieOptions);

  // Remove sensitive data from output
  user.password = undefined;

  res.status(statusCode).json({
    success: true,
    message,
    token,
    data: { user }
  });
};

module.exports = {
  generateToken,
  verifyToken,
  sendTokenResponse
};
`,

  userModel: `const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: {
      validator: function(email) {
        return /^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$/.test(email);
      },
      message: 'Please provide a valid email address'
    }
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters long'],
    select: false
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Index for better query performance
userSchema.index({ email: 1 });

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();

  try {
    const saltRounds = 12;
    this.password = await bcrypt.hash(this.password, saltRounds);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw new Error('Password comparison failed');
  }
};

// Update last login
userSchema.methods.updateLastLogin = function() {
  this.lastLogin = new Date();
  return this.save({ validateBeforeSave: false });
};

// Query middleware to exclude inactive users by default
userSchema.pre(/^find/, function(next) {
  if (!this.getOptions().includeInactive) {
    this.find({ isActive: { $ne: false } });
  }
  next();
});

const User = mongoose.model('User', userSchema);

module.exports = User;
`,

  authController: `const User = require('../models/User');
const ApiError = require('../utils/apiError');
const { sendTokenResponse } = require('../config/jwt');

// Register new user
const register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(new ApiError('User with this email already exists', 400));
    }

    // Create new user
    const user = await User.create({ name, email, password });

    sendTokenResponse(user, 201, res, 'User registered successfully');
  } catch (error) {
    next(error);
  }
};

// Login user
const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return next(new ApiError('Please provide both email and password', 400));
    }

    // Find user and include password
    const user = await User.findOne({ email }).select('+password');
    
    if (!user || !(await user.comparePassword(password))) {
      return next(new ApiError('Invalid email or password', 401));
    }

    // Update last login
    await user.updateLastLogin();

    sendTokenResponse(user, 200, res, 'Login successful');
  } catch (error) {
    next(error);
  }
};

// Logout user
const logout = (req, res) => {
  res.cookie('token', 'none', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });

  res.status(200).json({
    success: true,
    message: 'Logout successful'
  });
};

// Get current user profile
const getProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    
    res.status(200).json({
      success: true,
      data: { user }
    });
  } catch (error) {
    next(error);
  }
};

// Update user profile
const updateProfile = async (req, res, next) => {
  try {
    const allowedUpdates = ['name', 'email'];
    const updates = {};

    // Filter allowed updates
    Object.keys(req.body).forEach(key => {
      if (allowedUpdates.includes(key)) {
        updates[key] = req.body[key];
      }
    });

    if (Object.keys(updates).length === 0) {
      return next(new ApiError('No valid updates provided', 400));
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      updates,
      { new: true, runValidators: true }
    );

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: { user }
    });
  } catch (error) {
    next(error);
  }
};

// Deactivate user account
const deactivateAccount = async (req, res, next) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { isActive: false });

    res.status(200).json({
      success: true,
      message: 'Account deactivated successfully'
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  register,
  login,
  logout,
  getProfile,
  updateProfile,
  deactivateAccount
};
`,

  authMiddleware: `const jwt = require('jsonwebtoken');
const User = require('../models/User');
const ApiError = require('../utils/apiError');

// Protect routes - verify token
const authenticate = async (req, res, next) => {
  try {
    let token;

    // Get token from header or cookie
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.token) {
      token = req.cookies.token;
    }

    if (!token) {
      return next(new ApiError('Access denied. No token provided', 401));
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check if user still exists
    const user = await User.findById(decoded.id);
    if (!user) {
      return next(new ApiError('User no longer exists', 401));
    }

    // Grant access
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return next(new ApiError('Invalid token', 401));
    } else if (error.name === 'TokenExpiredError') {
      return next(new ApiError('Token expired', 401));
    }
    next(error);
  }
};

// Authorize specific roles
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new ApiError('Authentication required', 401));
    }

    if (!roles.includes(req.user.role)) {
      return next(new ApiError('Insufficient permissions', 403));
    }

    next();
  };
};

// Optional authentication - don't fail if no token
const optionalAuth = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.token) {
      token = req.cookies.token;
    }

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id);
      if (user) {
        req.user = user;
      }
    }

    next();
  } catch (error) {
    // Continue without user if token is invalid
    next();
  }
};

module.exports = {
  authenticate,
  authorize,
  optionalAuth
};
`,

  errorMiddleware: `const ApiError = require('../utils/apiError');

// Handle specific MongoDB errors
const handleCastError = (err) => {
  const message = \`Invalid \${err.path}: \${err.value}\`;
  return new ApiError(message, 400);
};

const handleDuplicateFields = (err) => {
  const field = Object.keys(err.keyValue)[0];
  const value = Object.values(err.keyValue)[0];
  const message = \`\${field} '\${value}' already exists\`;
  return new ApiError(message, 400);
};

const handleValidationError = (err) => {
  const errors = Object.values(err.errors).map(error => error.message);
  const message = \`Validation failed: \${errors.join('. ')}\`;
  return new ApiError(message, 400);
};

// Development error response
const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({
    success: false,
    error: {
      message: err.message,
      stack: err.stack,
      details: err
    }
  });
};

// Production error response
const sendErrorProd = (err, res) => {
  if (err.isOperational) {
    // Operational, trusted error: send message to client
    res.status(err.statusCode).json({
      success: false,
      message: err.message
    });
  } else {
    // Programming or other unknown error: don't leak error details
    console.error('ERROR:', err);
    
    res.status(500).json({
      success: false,
      message: 'Something went wrong on the server'
    });
  }
};

// Global error handler
module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, res);
  } else {
    let error = { ...err };
    error.message = err.message;

    // Handle specific MongoDB errors
    if (error.name === 'CastError') {
      error = handleCastError(error);
    }
    
    if (error.code === 11000) {
      error = handleDuplicateFields(error);
    }
    
    if (error.name === 'ValidationError') {
      error = handleValidationError(error);
    }

    sendErrorProd(error, res);
  }
};
`,

  authRoutes: `const express = require('express');
const {
  register,
  login,
  logout,
  getProfile,
  updateProfile,
  deactivateAccount
} = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

// Public routes
router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);

// Protected routes (authentication required)
router.use(authenticate);

router.get('/profile', getProfile);
router.patch('/profile', updateProfile);
router.delete('/account', deactivateAccount);

module.exports = router;
`,

  apiError: `class ApiError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = \`\${statusCode}\`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = ApiError;`,

  readme: `# ${projectName.charAt(0).toUpperCase() + projectName.slice(1)} API

A modern Node.js REST API built with Express.js and MongoDB, featuring user authentication, security middleware, and a clean architecture.

## Features

- 🔐 User authentication (register, login, logout)
- 🛡️ Security middleware (Helmet, CORS)
- 🗃️ MongoDB integration with Mongoose
- 🔑 JWT token-based authentication
- 📝 Input validation and sanitization
- 🚫 Comprehensive error handling
- 🍪 HTTP-only cookie support
- 🔒 Password hashing with bcrypt
- 📊 Health check endpoint
- 🎯 Role-based authorization
- ⚡ Clean and scalable architecture

## API Endpoints

### Authentication
\`\`\`
POST   /api/v1/auth/register      # Register new user
POST   /api/v1/auth/login         # Login user
POST   /api/v1/auth/logout        # Logout user
\`\`\`

### User Profile (Protected)
\`\`\`
GET    /api/v1/auth/profile       # Get user profile
PATCH  /api/v1/auth/profile       # Update user profile
DELETE /api/v1/auth/account       # Deactivate account
\`\`\`

### System
\`\`\`
GET    /health                    # Health check
\`\`\`

## Quick Start

### Prerequisites
- Node.js (v14 or higher)
- MongoDB (running locally or connection string)
- npm or yarn

### Installation

1. **Install dependencies**
   \`\`\`bash
   npm install
   \`\`\`

2. **Environment Setup**
   \`\`\`bash
   # Copy and configure environment variables
   cp .env.example .env
   \`\`\`

3. **Configure your .env file**
   \`\`\`env
   PORT=3000
   NODE_ENV=development
   MONGODB_URI=mongodb://localhost:27017/${projectName}
   JWT_SECRET=your-super-secret-jwt-key
   JWT_EXPIRES_IN=7d
   JWT_COOKIE_EXPIRES=7
   CORS_ORIGIN=http://localhost:3000
   \`\`\`

4. **Start the server**
   \`\`\`bash
   # Development mode with auto-reload
   npm run dev
   
   # Production mode
   npm start
   \`\`\`

## Project Structure

\`\`\`
src/
├── config/          # Configuration files
│   ├── db.js        # Database connection
│   └── jwt.js       # JWT utilities
├── controllers/     # Route handlers
│   └── authController.js
├── middleware/      # Custom middleware
│   ├── auth.js      # Authentication middleware
│   └── error.js     # Error handling middleware
├── models/          # Database models
│   └── User.js      # User model
├── routes/          # API routes
│   └── authRoutes.js
├── utils/           # Utility functions
│   └── apiError.js  # Custom error class
└── app.js          # Express application setup
\`\`\`

## Usage Examples

### Register a new user
\`\`\`bash
curl -X POST http://localhost:3000/api/v1/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "securePassword123"
  }'
\`\`\`

### Login
\`\`\`bash
curl -X POST http://localhost:3000/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "john@example.com",
    "password": "securePassword123"
  }'
\`\`\`

### Access protected route
\`\`\`bash
curl -X GET http://localhost:3000/api/v1/auth/profile \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
\`\`\`

## Security Features

- **Password Hashing**: bcrypt with salt rounds
- **JWT Authentication**: HTTP-only cookies + Authorization header support
- **CORS Protection**: Configurable origin restrictions
- **Security Headers**: Helmet.js for security headers
- **Input Validation**: Mongoose schema validation
- **Error Handling**: No sensitive data leakage
- **Rate Limiting**: Ready for implementation

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| \`PORT\` | Server port | \`3000\` |
| \`NODE_ENV\` | Environment mode | \`development\` |
| \`MONGODB_URI\` | MongoDB connection string | Required |
| \`JWT_SECRET\` | JWT signing secret | Required |
| \`JWT_EXPIRES_IN\` | Token expiration time | \`7d\` |
| \`JWT_COOKIE_EXPIRES\` | Cookie expiration (days) | \`7\` |
| \`CORS_ORIGIN\` | Allowed CORS origin | \`http://localhost:3000\` |

## Development

### Available Scripts

\`\`\`bash
npm run dev     # Start development server with nodemon
npm start       # Start production server
npm test        # Run tests (to be implemented)
\`\`\`

### Code Structure

- **Controllers**: Handle business logic and request/response
- **Middleware**: Reusable functions for auth, validation, error handling
- **Models**: Database schemas and model methods
- **Routes**: API endpoint definitions
- **Utils**: Helper functions and custom classes
- **Config**: Database connection and JWT utilities

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For support, please open an issue in the repository or contact the maintainer.
`
};

// Create project structure
try {
  log.info('Creating project structure...');
  
  // Create main directory
  createDirectory(projectPath);
  
  // Create subdirectories
  const directories = [
    'src',
    'src/config',
    'src/controllers',
    'src/middleware',
    'src/models',
    'src/routes',
    'src/utils'
  ];
  
  directories.forEach(dir => {
    createDirectory(path.join(projectPath, dir));
  });
  
  log.success('Project directories created');
  
  // Write files
  const filesToWrite = [
    { path: 'package.json', content: JSON.stringify(templates.packageJson, null, 2) },
    { path: '.gitignore', content: templates.gitignore },
    { path: '.env', content: templates.envTemplate },
    { path: 'README.md', content: templates.readme },
    { path: 'src/app.js', content: templates.appJs },
    { path: 'src/config/db.js', content: templates.dbConfig },
    { path: 'src/config/jwt.js', content: templates.jwtConfig },
    { path: 'src/models/User.js', content: templates.userModel },
    { path: 'src/controllers/authController.js', content: templates.authController },
    { path: 'src/middleware/auth.js', content: templates.authMiddleware },
    { path: 'src/middleware/error.js', content: templates.errorMiddleware },
    { path: 'src/routes/authRoutes.js', content: templates.authRoutes },
    { path: 'src/utils/apiError.js', content: templates.apiError }
  ];
  
  filesToWrite.forEach(file => {
    fs.writeFileSync(path.join(projectPath, file.path), file.content);
  });
  
  log.success('All files created successfully');
  
  // Install dependencies
  log.info('Installing dependencies...');
  process.chdir(projectPath);
  execSync('npm install', { stdio: 'inherit' });
  log.success('Dependencies installed');
  
  // Success message
  console.log('');
  log.title('🎉 Project created successfully!');
  console.log('');
  log.info('Next steps:');
  console.log('');
  console.log(`  cd ${projectName}`);
  console.log('  npm run dev');
  console.log('');
  log.warn('Remember to:');
  console.log('  • Start MongoDB server');
  console.log('  • Configure your .env file');
  console.log('  • Change JWT_SECRET to a secure value');
  console.log('');
  log.info('API will be available at http://localhost:3000');
  log.info('Health check: http://localhost:3000/health');
  console.log('');
  
} catch (error) {
  log.error(`Failed to create project: ${error.message}`);
  process.exit(1);
}