# Create Node API

A powerful CLI tool to scaffold modern Node.js REST API projects with Express.js, MongoDB, and built-in authentication system.

## Features

🚀 **Quick Setup**: Generate a complete API project in seconds  
🛡️ **Security First**: Built-in authentication, password hashing, and security middleware  
📁 **Clean Architecture**: Well-organized folder structure following industry best practices  
🔧 **Ready to Use**: All dependencies configured and ready to run  
📚 **Documentation**: Complete README with API documentation and examples  
⚡ **Modern Stack**: Express.js, MongoDB, JWT, bcrypt, and more

## Installation

### Global Installation (Recommended)

```bash
npm install -g node-api-genie
```

### One-time Usage (npx)

```bash
npx node-api-genie my-awesome-api
```

## Usage

```bash
node-api-genie <project-name>
```

### Example

```bash
node-api-genie my-awesome-api
cd my-awesome-api
npm run dev
```

## Generated Project Structure

```
my-awesome-api/
├── src/
│   ├── config/
│   │   ├── db.js              # Database connection setup
│   │   └── jwt.js             # JWT utilities and helpers
│   ├── controllers/
│   │   └── authController.js  # Authentication business logic
│   ├── middleware/
│   │   ├── auth.js            # Authentication middleware
│   │   └── error.js           # Global error handling
│   ├── models/
│   │   └── User.js            # User database model
│   ├── routes/
│   │   └── authRoutes.js      # API route definitions
│   ├── utils/
│   │   └── apiError.js        # Custom error handling class
│   └── app.js                 # Express application setup
├── .env                       # Environment configuration
├── .gitignore                # Git ignore rules
├── package.json              # Project metadata and dependencies
└── README.md                 # Comprehensive project documentation
```

## Generated Features

### 🔐 Authentication System
- **POST** `/api/v1/auth/register` - User registration with validation
- **POST** `/api/v1/auth/login` - Secure user login with JWT
- **POST** `/api/v1/auth/logout` - Safe user logout

### 👤 User Management
- **GET** `/api/v1/auth/profile` - Get authenticated user profile
- **PATCH** `/api/v1/auth/profile` - Update user information
- **DELETE** `/api/v1/auth/account` - Deactivate user account

### 🛡️ Security Features
- Password hashing with bcryptjs (12 salt rounds)
- JWT token authentication with configurable expiration
- HTTP-only cookie support for enhanced security
- CORS protection with configurable origins
- Helmet.js for security headers
- Input validation and sanitization
- Comprehensive error handling without data leakage
- Role-based authorization system

### 📦 Included Dependencies
- **express** - Fast web framework for Node.js
- **mongoose** - MongoDB object modeling
- **bcryptjs** - Password hashing library
- **jsonwebtoken** - JWT implementation
- **cookie-parser** - Cookie parsing middleware
- **dotenv** - Environment variable management
- **helmet** - Security middleware collection
- **cors** - Cross-Origin Resource Sharing
- **nodemon** - Development auto-reload (dev dependency)

## Quick Start Guide

1. **Create your project**:
   ```bash
   create-node-api my-api
   cd my-api
   ```

2. **Start MongoDB** (ensure MongoDB is running on your system)

3. **Configure environment**:
   ```bash
   # The .env file is automatically created with defaults
   # Update these values for your setup:
   PORT=3000
   MONGODB_URI=mongodb://localhost:27017/my-api
   JWT_SECRET=your-super-secure-secret-key
   JWT_EXPIRES_IN=7d
   NODE_ENV=development
   ```

4. **Install dependencies and start**:
   ```bash
   npm install  # Already done automatically
   npm run dev  # Start development server
   ```

5. **Test your API**:
   ```bash
   # Health check
   curl http://localhost:3000/health
   
   # Register a user
   curl -X POST http://localhost:3000/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{"name":"John Doe","email":"john@example.com","password":"password123"}'
   ```

## Project Architecture

### Clean Architecture Pattern
The generated project follows a clean, scalable architecture:

- **app.js** - Application entry point and Express setup
- **config/** - Configuration files for database and utilities
- **controllers/** - Business logic and request handling
- **middleware/** - Reusable middleware functions
- **models/** - Database schemas and model definitions
- **routes/** - API endpoint definitions
- **utils/** - Helper functions and custom classes

### Design Patterns Used
- **MVC Pattern** - Separation of concerns
- **Middleware Pattern** - Reusable request processing
- **Repository Pattern** - Database abstraction
- **Factory Pattern** - Error creation and handling
- **Singleton Pattern** - Database connection management

## API Examples

### Authentication Flow

```bash
# 1. Register a new user
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Jane Smith",
    "email": "jane@example.com",
    "password": "securePassword123"
  }'

# Response:
# {
#   "success": true,
#   "message": "User registered successfully",
#   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
#   "data": {
#     "user": {
#       "_id": "...",
#       "name": "Jane Smith",
#       "email": "jane@example.com",
#       "role": "user"
#     }
#   }
# }

# 2. Login
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "jane@example.com",
    "password": "securePassword123"
  }'

# 3. Access protected route
curl -X GET http://localhost:3000/api/v1/auth/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Environment Configuration

The generated `.env` file includes all necessary configuration:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database Configuration  
MONGODB_URI=mongodb://localhost:27017/your-project-name

# Security Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=7d
JWT_COOKIE_EXPIRES=7

# CORS Configuration
CORS_ORIGIN=http://localhost:3000
```

## Customization

The generated project is fully customizable:

### Adding New Routes
```javascript
// src/routes/newRoutes.js
const express = require('express');
const router = express.Router();

router.get('/example', (req, res) => {
  res.json({ message: 'Hello World!' });
});

module.exports = router;
```

### Adding New Models
```javascript
// src/models/Product.js
const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true }
}, { timestamps: true });

module.exports = mongoose.model('Product', productSchema);
```

## Development Workflow

```bash
# Development mode (auto-reload)
npm run dev

# Production mode
npm start

# Install additional packages
npm install package-name

# Run with specific environment
NODE_ENV=production npm start
```

## Production Deployment

The generated project is production-ready:

1. **Environment Variables**: Configure production values
2. **Database**: Use MongoDB Atlas or your preferred MongoDB service
3. **Security**: Update JWT_SECRET to a cryptographically strong value
4. **HTTPS**: Enable secure cookies in production
5. **Process Management**: Use PM2 or similar for process management

## Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- 📝 **Documentation**: Full API documentation included
- 🐛 **Issues**: Report bugs on GitHub
- 💬 **Discussions**: Join the community discussions
- 📧 **Contact**: Reach out to maintainers

## What's Next?

After generating your project, consider adding:

- API rate limiting
- Email verification system
- Password reset functionality
- API documentation with Swagger
- Unit and integration tests
- Docker containerization
- CI/CD pipeline setup

---

**Happy coding! 🚀**