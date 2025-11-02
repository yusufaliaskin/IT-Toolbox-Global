# IT Toolbox - Web-Based IT Tools Catalog & User Management System

![Kayıt 2025-03-27 013519](https://github.com/user-attachments/assets/3f5b6e68-219a-4aa2-b937-65a0b34c6231)

## 📋 Overview

IT Toolbox is a comprehensive web application built with Flask that serves as a centralized catalog of essential tools and software for IT professionals. The application features a robust user authentication system, role-based access control, two-factor authentication, and an organized collection of IT tools categorized by their purpose.

## ✨ Key Features

### 🔐 Authentication & Security
- **User Registration & Login System**: Secure user authentication with password hashing
- **Two-Factor Authentication (2FA)**: TOTP-based 2FA with QR code generation for enhanced security
- **Role-Based Access Control**: Admin and user roles with different permission levels
- **Activity Logging**: Track user login activities including device, IP address, and timestamp
- **Session Management**: Secure session handling with "Remember Me" functionality
- **Password Management**: Secure password update functionality

### 👤 User Management
- **User Profiles**: Customizable user profiles with bio, profile images, and personal information
- **Profile Image Upload**: Support for PNG, JPG, JPEG, and GIF formats
- **Admin Panel**: Complete user management dashboard for administrators
  - Add new users
  - Edit existing users
  - Delete user accounts
  - View all registered users
- **Notification Preferences**: Configurable notification settings for blog updates, newsletters, and offers

### 🛠️ IT Tools Catalog
- **Categorized Tools**: Tools organized into categories:
  - Ana Araçlar (Main Tools)
  - Yapay Zeka Araçları (AI Tools)
  - Tarayıcılar (Browsers)
  - İş Zekası Araçları (Business Intelligence Tools)
- **Search Functionality**: Quick search across all tools and categories
- **Category Filtering**: Browse tools by specific categories
- **External Links**: Direct access to download or use each tool

### 🎨 User Interface
- **Responsive Design**: Mobile-friendly interface
- **Intuitive Navigation**: Easy-to-use navigation bar with dropdown menus
- **Profile Avatar Display**: Visual user identification in the navbar
- **Modern UI**: Clean and professional design

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Step 1: Clone the Repository
```bash
git clone https://github.com/yusufaliaskin/IT-Toolbox.git
cd IT-Toolbox
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Create Required Directories
The application will automatically create the `static/uploads` directory for profile images when you run it for the first time.

### Step 4: Initialize the Database
The SQLite database (`users.db`) will be automatically created when you first run the application, including a default admin account.

## 🏃 Running the Application

### Start the Flask Development Server
```bash
python app.py
```

The application will start on `http://127.0.0.1:5000/`

### Access the Application
1. Open your web browser
2. Navigate to `http://127.0.0.1:5000/`
3. You'll be redirected to the homepage

## 👥 Default Admin Account

After the first run, a default admin account is created:

- **Username**: `admin`
- **Email**: `hi@admin.com`
- **Password**: `123`

⚠️ **IMPORTANT**: Change the default admin password immediately after first login for security purposes!

## 📁 Project Structure

```
IT-Toolbox/
├── app.py                     # Main Flask application with all routes and logic
├── models.py                  # User model and repository classes (legacy)
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
├── project_structure.md       # Detailed project structure documentation
├── users.db                   # SQLite database (created automatically)
├── static/                    # Static assets
│   ├── auth.css              # Authentication page styles
│   ├── auth.js               # Authentication page JavaScript
│   ├── profiles.css          # Profile page styles
│   ├── styles.css            # Global styles
│   ├── data/
│   │   └── programs.json     # IT tools catalog data
│   └── uploads/              # User profile images (created automatically)
└── templates/                 # HTML templates
    ├── auth.html             # Login/Register page
    ├── edit_user.html        # User editing page (admin)
    ├── index.html            # Homepage with tools catalog
    ├── manage_users.html     # User management dashboard (admin)
    ├── profiles.html         # User profile page
    ├── security.html         # Security settings page
    └── setup_2fa.html        # 2FA setup page with QR code
```

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    first_name TEXT,
    last_name TEXT,
    bio TEXT,
    profile_image TEXT,
    role TEXT DEFAULT 'user',
    joined_date TEXT,
    notifications_blog INTEGER DEFAULT 1,
    notifications_news INTEGER DEFAULT 1,
    notifications_offers INTEGER DEFAULT 1,
    activity_logs INTEGER DEFAULT 0,
    two_factor_auth INTEGER DEFAULT 0,
    pin_code_enabled INTEGER DEFAULT 0,
    two_factor_secret TEXT
);
```

### User Activities Table
```sql
CREATE TABLE user_activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    device TEXT,
    ip_address TEXT,
    location TEXT,
    timestamp TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## 🔧 Configuration

### Security Settings
Update the secret key in `app.py` for production use:
```python
app.secret_key = 'your-secret-key-here'  # Change this to a random secret key
```

Generate a secure secret key:
```python
import secrets
print(secrets.token_hex(32))
```

### File Upload Settings
Allowed profile image formats are defined in `app.py`:
```python
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
```

### Adding New Tools
Edit `static/data/programs.json` to add new tools or categories:
```json
[
  {
    "name": "Category Name",
    "programs": [
      {
        "name": "Tool Name",
        "description": "Tool description",
        "url": "https://example.com"
      }
    ]
  }
]
```

## 📚 API Routes

### Public Routes
- `GET /` - Homepage with tools catalog
- `GET /category/<category_name>` - Filter tools by category
- `GET /search?q=<query>` - Search tools
- `GET /auth` - Login/Register page
- `POST /auth` - Handle login/register/2FA verification
- `GET /forgot_password` - Password recovery (placeholder)

### Protected Routes (Login Required)
- `GET /profiles` - User profile page
- `POST /update_profile` - Update user profile
- `POST /update_password` - Change password
- `POST /update_photo` - Upload profile image
- `GET /security` - Security settings page
- `POST /toggle_activity_logs` - Enable/disable activity logging
- `POST /toggle_two_factor_auth` - Enable/disable 2FA
- `GET /setup_2fa` - 2FA setup with QR code
- `POST /toggle_pin_code` - Enable/disable PIN code
- `GET /logout` - Logout user

### Admin Routes (Admin Role Required)
- `GET /manage_users` - User management dashboard
- `POST /add_new_user` - Create new user
- `GET /edit_user/<user_id>` - Edit user form
- `POST /edit_user/<user_id>` - Update user
- `GET /delete_user/<user_id>` - Delete user

## 🔒 Security Best Practices

1. **Change Default Credentials**: Update the admin password immediately
2. **Use Strong Secret Key**: Generate and use a strong secret key in production
3. **Enable 2FA**: Enable two-factor authentication for enhanced security
4. **Regular Updates**: Keep dependencies updated
5. **HTTPS**: Use HTTPS in production environments
6. **Database Backups**: Regularly backup the `users.db` file

## 🛠️ Dependencies

- **Flask** (2.0.1): Web framework
- **Flask-Login** (0.5.0): User session management
- **Werkzeug** (2.0.1): Password hashing and security utilities
- **pyotp** (2.8.0): TOTP-based two-factor authentication
- **qrcode** (7.3.1): QR code generation for 2FA
- **user-agents** (2.2.0): Parse user agent strings for activity logs
- **python-dotenv** (0.19.0): Environment variable management
- **python-ldap** (3.4.0): LDAP integration (legacy, not actively used)

## 🐛 Troubleshooting

### Issue: Database not created
**Solution**: Ensure you have write permissions in the project directory. The database is created automatically on first run.

### Issue: Profile images not uploading
**Solution**: Verify the `static/uploads/` directory exists and has write permissions.

### Issue: 2FA QR code not displaying
**Solution**: Ensure the `qrcode` and `pyotp` libraries are properly installed.

### Issue: Import errors
**Solution**: Reinstall dependencies with `pip install -r requirements.txt`

## 🚀 Production Deployment

For production deployment:

1. Use a production WSGI server (Gunicorn, uWSGI)
2. Set `debug=False` in `app.py`
3. Use environment variables for sensitive configuration
4. Set up a reverse proxy (Nginx, Apache)
5. Use PostgreSQL or MySQL instead of SQLite for better performance
6. Implement proper logging
7. Set up SSL/TLS certificates

### Example with Gunicorn:
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

## 📝 License

MIT License

Copyright (c) 2025 IT Toolbox Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## 👨‍💻 Maintainer

**Yusuf Ali Aşkın**
- GitHub: [@yusufaliaskin](https://github.com/yusufaliaskin)
- LinkedIn: [Yusuf Aşkın](https://www.linkedin.com/in/yusuf-aşkın-56015b232/)
- Instagram: [@joseph.ddf](https://www.instagram.com/joseph.ddf/)
- Email: yusufaliaskin@gmail.com

## 🙏 Credits

Original concept by [JosephSpace](https://github.com/JosephSpace/IT-Toolbox)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

**⭐ If you find this project useful, please consider giving it a star!**
