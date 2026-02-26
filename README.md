# Secure Student Record Blockchain System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-AES%20%2B%20SHA256%20%2B%20PBFT-red.svg)](#security-features)

A production-quality blockchain-based secure education data management system built with Python and Flask. This system provides credible and tamper-proof storage of student academic records using advanced cryptography, custom blockchain implementation, and PBFT consensus mechanism.

## 🚀 Features

### 🔐 Security Features
- **Data Encryption**: Fernet (AES 128) with PBKDF2 key derivation
- **Data Integrity**: SHA-256 hashing for all records
- **Data Masking**: Intelligent masking of sensitive information
- **Blockchain Verification**: Custom blockchain with immutable record hashes
- **PBFT Consensus**: 3-node Byzantine Fault Tolerant consensus simulation
- **Audit Logging**: Comprehensive access and action logging

### 👥 Role-Based Access Control
- **Admin**: Upload and manage all student records, view system statistics
- **Student**: Access own records, grant permissions to verifiers
- **Verifier**: Verify record authenticity with proper authorization

### ⛓️ Blockchain Features
- **Custom Blockchain**: Private blockchain implementation
- **Smart Contract Simulation**: Permission-based access control
- **PBFT Consensus**: Simulated 3-node consensus validation
- **Integrity Verification**: Cross-reference database and blockchain hashes

## 🏗️ System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Flask Web     │    │   Security       │    │   Blockchain    │
│   Application   │◄──►│   Layer          │◄──►│   Layer         │
│                 │    │                  │    │                 │
│ • REST API      │    │ • Encryption     │    │ • Custom Chain  │
│ • Authentication│    │ • Hashing        │    │ • PBFT Consensus│
│ • Authorization │    │ • Data Masking   │    │ • Verification  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                     ┌──────────────────┐
                     │   SQLite         │
                     │   Database       │
                     │                  │
                     │ • User Records   │
                     │ • Encrypted Data │
                     │ • Access Logs    │
                     │ • Permissions    │
                     └──────────────────┘
```

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Git

### 1. Clone the Repository
```bash
git clone <repository-url>
cd secure-student-record-blockchain
```

### 2. Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\\Scripts\\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Environment Configuration (Optional)
Create a `.env` file in the project root:
```env
# Flask Configuration
SECRET_KEY=your-super-secret-key-change-in-production
FLASK_ENV=development

# Security Configuration
ENCRYPTION_MASTER_PASSWORD=your-encryption-password
HASHING_SALT=your-hashing-salt

# Database Configuration
DATABASE_PATH=secure_student_records.db
BLOCKCHAIN_DATA_FILE=blockchain_data.json

# Logging
LOG_LEVEL=INFO
```

### 5. Initialize and Run
```bash
python app.py
```

The system will be available at `http://localhost:5000`

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /auth/register
Content-Type: application/json

{
    "username": "admin_user",
    "email": "admin@university.edu",
    "password": "securepassword123",
    "role": "admin"
}
```

#### Login
```http
POST /auth/login
Content-Type: application/json

{
    "username": "admin_user",
    "password": "securepassword123"
}
```

### Record Management Endpoints

#### Upload Student Record (Admin Only)
```http
POST /records/upload
Content-Type: application/json
Cookie: session=<session_cookie>

{
    "student_id": "STU123456",
    "record_type": "transcript",
    "record_data": {
        "student_name": "John Smith",
        "student_id": "STU123456",
        "institution": "University of Technology",
        "program": "Computer Science",
        "semester": "Fall 2024",
        "courses": [
            {
                "course": "CS101",
                "grade": "A",
                "credits": 3
            },
            {
                "course": "MATH201", 
                "grade": "B+",
                "credits": 4
            }
        ],
        "gpa": 3.75
    }
}
```

#### View Student Records
```http
GET /records/view/STU123456
Cookie: session=<session_cookie>
```

#### Verify Record Authenticity
```http
GET /records/verify/STU123456/1
Cookie: session=<session_cookie>
```

## 🔧 Configuration

The system uses a three-tier configuration system:

### Development Configuration (`DevelopmentConfig`)
- Debug mode enabled
- Relaxed security settings
- Verbose logging
- In-memory or file-based database

### Testing Configuration (`TestingConfig`)
- Testing mode enabled
- Disabled external services
- Fast encryption settings
- In-memory database

### Production Configuration (`ProductionConfig`)
- Enhanced security
- HTTPS requirements
- Rate limiting
- Error reporting
- Backup systems

## 🏛️ Data Flow & Workflow

### Record Upload Process
1. **Admin uploads record** → Data validation
2. **Data masking** → Sensitive fields masked for display
3. **Data encryption** → Full data encrypted with Fernet (AES)
4. **Hash generation** → SHA-256 hash of original data
5. **Database storage** → Encrypted data saved to SQLite
6. **PBFT validation** → 3-node consensus validation
7. **Blockchain storage** → Hash added to blockchain (if validated)
8. **Verification complete** → Record marked as verified

### Record Access Process
1. **User authentication** → Role-based access check
2. **Permission validation** → Smart contract-like permission system
3. **Data retrieval** → Encrypted data from database
4. **Data decryption** → Decrypt for authorized users
5. **Data masking** → Apply appropriate masking level
6. **Audit logging** → Log access attempt
7. **Response delivery** → Return appropriate data level

### Record Verification Process
1. **Verifier request** → Check verifier permissions
2. **Hash comparison** → Compare database vs blockchain hash
3. **Integrity check** → Verify data hasn't been tampered with
4. **Blockchain validation** → Validate entire blockchain integrity
5. **Consensus verification** → Check PBFT consensus history
6. **Verification report** → Detailed authenticity report

## 🔐 Security Features

### Encryption
- **Algorithm**: Fernet (AES 128 in CBC mode with HMAC)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Salt**: Randomly generated per installation
- **Data**: All student records encrypted before storage

### Hashing
- **Algorithm**: SHA-256
- **Usage**: Data integrity verification, blockchain operations
- **Salt**: Configurable salt for additional security
- **Verification**: Cross-reference hashes for authenticity

### Data Masking
- **Levels**: Low, Medium, High masking levels
- **Fields**: Student IDs, emails, grades, financial data
- **Patterns**: Partial masking, full masking, format-preserving
- **Context**: Role-based masking application

### Blockchain Security
- **Consensus**: PBFT (Practical Byzantine Fault Tolerance)
- **Nodes**: 3-node simulation with majority consensus
- **Immutability**: Cryptographically linked blocks
- **Verification**: Multi-level integrity checking

## 🧪 Testing

### Run Tests
```bash
# Install test dependencies
pip install pytest pytest-flask pytest-cov

# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test categories
pytest tests/test_blockchain.py
pytest tests/test_security.py
pytest tests/test_api.py
```

### Test Coverage Areas
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing
- **Security Tests**: Encryption, hashing, access control
- **Blockchain Tests**: Consensus, integrity, validation
- **API Tests**: All endpoints and error conditions

## 🚀 Production Deployment

### Using Gunicorn (Recommended)
```bash
# Install Gunicorn
pip install gunicorn

# Run with 4 worker processes
gunicorn --bind 0.0.0.0:8000 --workers 4 app:app

# With configuration file
gunicorn --config gunicorn.conf.py app:app
```

### Environment Variables for Production
```bash
export FLASK_ENV=production
export SECRET_KEY=your-production-secret-key
export DATABASE_PATH=/var/lib/secure_records/secure_student_records.db
export BLOCKCHAIN_DATA_FILE=/var/lib/secure_records/blockchain_data.json
export ENCRYPTION_MASTER_PASSWORD=your-strong-encryption-password
export LOG_LEVEL=WARNING
```

### Docker Deployment
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "app:app"]
```

## 📊 System Monitoring

### Health Check
```http
GET /health
```

### System Statistics (Admin Only)
```http
GET /records/statistics
```

### Blockchain Information
```http
GET /records/blockchain/info
```

## 🔍 Troubleshooting

### Common Issues

#### Database Connection Errors
```bash
# Check database file permissions
ls -la secure_student_records.db

# Reinitialize database
rm secure_student_records.db
python app.py
```

#### Encryption Key Issues
```bash
# Remove old salt and regenerate
rm encryption_salt.key
python app.py
```

#### Session Problems
```bash
# Clear browser cookies
# Check SESSION_COOKIE_SECURE setting
# Verify SECRET_KEY configuration
```

## 📈 Performance Considerations

### Database Optimization
- **Indexes**: Automatic SQLite indexes on foreign keys
- **Connection Pooling**: Built-in SQLite connection management
- **Query Optimization**: Parameterized queries prevent SQL injection

### Blockchain Performance
- **Difficulty Adjustment**: Configurable mining difficulty
- **Block Size Limits**: 1MB maximum per block
- **Consensus Timeout**: 30-second PBFT timeout

### Caching Strategy
- **Session Caching**: Flask session management
- **Query Caching**: Implement Redis for frequent queries (future)
- **Static Assets**: Use CDN for static content delivery

## 🛡️ Security Best Practices

### For Development
- Use strong `SECRET_KEY`
- Set custom `ENCRYPTION_MASTER_PASSWORD`
- Enable debug mode only in development
- Use HTTPS in production

### For Production
- Use environment variables for sensitive data
- Enable all security headers
- Implement rate limiting
- Set up monitoring and logging
- Regular security audits
- Backup encryption keys securely

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

For technical support and questions:

- **Documentation**: Visit `/api-docs` endpoint for detailed API documentation
- **Issues**: Create GitHub issues for bugs and feature requests
- **Security**: Report security vulnerabilities via private channels

## 🎯 Future Enhancements

- [ ] Multi-institution support
- [ ] Mobile application
- [ ] Advanced analytics dashboard
- [ ] Integration with external verification services
- [ ] Enhanced consensus algorithms
- [ ] Distributed blockchain network
- [ ] AI-powered fraud detection
- [ ] Advanced search capabilities

---

**Built with ❤️ for secure education data management**