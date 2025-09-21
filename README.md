# SoftPOS API Backend

A comprehensive FastAPI-based backend for Software Point of Sale (SoftPOS) systems with enterprise-grade Role-Based Access Control (RBAC).

## Features

### Core Functionality
- **Role-Based Access Control (RBAC)** - Comprehensive permission system with 20+ roles and 67+ granular permissions
- **Multi-tenant Architecture** - Support for multiple merchants with data isolation
- **Approval Workflows** - Built-in approval system for sensitive operations
- **Audit Logging** - Complete audit trail for all system actions
- **Session Management** - Secure session handling with timeout and IP validation

### Security Features
- JWT-based authentication with session validation
- Multi-factor authentication (2FA) support
- Hardware key authentication for sensitive operations
- IP allowlisting and geographic restrictions
- Comprehensive audit trails and compliance logging

### RBAC System
The system includes predefined roles such as:
- **Super Admin** - Full system access
- **Customer Service Agent** - Customer support operations
- **Risk Analyst** - Risk management and fraud detection
- **Merchant Admin** - Merchant-level administration
- **Developer** - API and system development access
- And 15+ additional specialized roles

## Tech Stack

- **FastAPI** - Modern Python web framework
- **SQLAlchemy 2.0** - Async ORM with type safety
- **PostgreSQL** - Primary database
- **Alembic** - Database migrations
- **pytest** - Testing framework
- **structlog** - Structured logging
- **Pydantic** - Data validation and serialization

## Installation

### Prerequisites
- Python 3.9+
- PostgreSQL 12+
- Git

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/smbabalola/SoftPOS-Backend.git
   cd SoftPOS-Backend
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your database and security settings
   ```

5. **Database setup**
   ```bash
   alembic upgrade head
   ```

6. **Initialize RBAC system**
   ```bash
   python -m app.rbac.init_roles
   ```

## Running the Application

### Development
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Production
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`
API documentation at `http://localhost:8000/docs`

## Testing

### Run all tests
```bash
pytest
```

### Run RBAC tests specifically
```bash
python run_rbac_tests.py
```

### Run with coverage
```bash
pytest --cov=app tests/
```

## RBAC System

### Permissions
The system uses a hierarchical permission structure:
- **Resource Types**: merchant, transaction, payout, user, system
- **Actions**: read, write, delete, admin, approve
- **Scopes**: global, merchant-specific, user-specific

### Role Assignment
```python
# Assign role to user
await rbac_service.assign_role_to_user(
    user=user,
    role_name="merchant_admin",
    assigned_by=admin_user,
    scope_type="merchant",
    scope_id="mer_123"
)
```

### Permission Checking
```python
# Check permission
has_permission = await rbac_service.check_permission(
    user=user,
    permission_name="transaction_refund",
    amount=10000,
    resource_type="transaction"
)
```

### Using Decorators
```python
@require_permission("merchant_read")
@require_2fa
async def get_merchant_data(merchant_id: str):
    return {"merchant": "data"}
```

## API Endpoints

### Authentication
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `POST /auth/refresh` - Refresh token

### RBAC Management
- `GET /rbac/roles` - List all roles
- `POST /rbac/roles/{role_id}/assign` - Assign role to user
- `DELETE /rbac/roles/{role_id}/revoke` - Revoke role from user
- `GET /rbac/permissions` - List user permissions
- `GET /rbac/audit` - Audit trail

### Approval Workflows
- `POST /approvals/create` - Create approval request
- `POST /approvals/{workflow_id}/approve` - Approve request
- `POST /approvals/{workflow_id}/reject` - Reject request

## Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost/softpos

# Security
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# RBAC
RBAC_CONFIG_PATH=config/rbac_config.yaml
AUDIT_LOG_RETENTION_DAYS=365
```

### RBAC Configuration
The RBAC system is configured via `config/rbac_config.yaml`:
```yaml
roles:
  super_admin:
    display_name: "Super Admin"
    user_type: "platform_admin"
    requires_2fa: true
    session_timeout_minutes: 480

permissions:
  merchant_read:
    display_name: "Read Merchant Data"
    resource_type: "merchant"
    action: "read"
```

## Deployment

### Railway (Recommended - Free)
1. Push to GitHub
2. Connect Railway to your repository
3. Set environment variables
4. Deploy automatically

### Docker
```bash
docker build -t softpos-api .
docker run -p 8000:8000 softpos-api
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Email: smbabalola@yahoo.com
- Create an issue on GitHub
