# Quotes Management API

A professional Go backend API for managing quotes with user authentication, role-based access control, and audit logging.

## Features

- **User Registration & Authentication**: API key-based authentication
- **Role-based Access Control**: Admin and User roles
- **Quotes Management**: Add, view quotes with author information
- **Admin Panel**: User management, deactivation/reactivation
- **Audit Logging**: Track all system activities
- **SQLite Database**: Lightweight, embedded database
- **RESTful API**: Clean, professional API design

## Project Structure

```
quotes-api/
├── main.go              # Main application file
├── go.mod              # Go module dependencies
├── quotes.db           # SQLite database (auto-created)
├── README.md           # This file
└── Quotes_API.postman_collection.json  # Postman test collection
```

## Prerequisites

- Go 1.21 or higher
- Git (for cloning)

## Installation & Setup

### 1. Clone or Create Project

```bash
mkdir quotes-api
cd quotes-api
```

### 2. Initialize Go Module

```bash
go mod init quotes-api
```

### 3. Create main.go

Copy the provided `main.go` content into your project directory.

### 4. Create go.mod

Copy the provided `go.mod` content or run:

```bash
go mod tidy
```

### 5. Install Dependencies

```bash
go get github.com/gorilla/mux
go get github.com/mattn/go-sqlite3
go get github.com/rs/cors
go get golang.org/x/crypto
```

### 6. Run the Application

```bash
go run main.go
```

The server will start on `http://localhost:8080`

## Default Admin Account

- **Email**: `Shariar@gmail.com`
- **Password**: `Alpha1234`
- **Role**: `admin`

## API Endpoints

### Public Endpoints (No Authentication Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Check API health status |
| GET | `/quotes` | View all quotes (public) |
| GET | `/quotes/{id}` | Get specific quote by ID |
| POST | `/register` | Register new user |
| POST | `/admin/login` | Admin login |

### User Endpoints (Require API Key)

| Method | Endpoint | Description | Header Required |
|--------|----------|-------------|-----------------|
| POST | `/quotes` | Add new quote | `X-API-Key` |

### Admin Endpoints (Require Admin API Key)

| Method | Endpoint | Description | Header Required |
|--------|----------|-------------|-----------------|
| GET | `/admin/users` | View all users | `X-API-Key` (Admin) |
| PUT | `/admin/users/{id}/deactivate` | Deactivate user | `X-API-Key` (Admin) |
| PUT | `/admin/users/{id}/reactivate` | Reactivate user | `X-API-Key` (Admin) |
| GET | `/admin/audit-logs` | View audit logs | `X-API-Key` (Admin) |

## API Usage Examples

### 1. Check API Health

```bash
curl -X GET http://localhost:8080/health
```

### 2. Admin Login

```bash
curl -X POST http://localhost:8080/admin/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "Shariar@gmail.com",
    "password": "Alpha1234"
  }'
```

### 3. Register User

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "userpass123"
  }'
```

### 4. Add Quote (with API Key)

```bash
curl -X POST http://localhost:8080/quotes \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY_HERE" \
  -d '{
    "quote": "The only way to do great work is to love what you do.",
    "author": "Steve Jobs"
  }'
```

### 5. View All Quotes

```bash
curl -X GET http://localhost:8080/quotes
```

### 6. Get Specific Quote

```bash
curl -X GET http://localhost:8080/quotes/1
```

## Database Schema

### Users Table
- `id` (INTEGER, PRIMARY KEY)
- `email` (TEXT, UNIQUE)
- `password` (TEXT, hashed)
- `role` (TEXT: 'user' or 'admin')
- `api_key` (TEXT, UNIQUE)
- `is_active` (BOOLEAN)
- `created_at` (DATETIME)

### Quotes Table
- `id` (INTEGER, PRIMARY KEY)
- `quote` (TEXT)
- `author` (TEXT)
- `user_id` (INTEGER, FOREIGN KEY)
- `created_at` (DATETIME)

### Audit Logs Table
- `id` (INTEGER, PRIMARY KEY)
- `user_id` (INTEGER, FOREIGN KEY)
- `action` (TEXT)
- `details` (TEXT)
- `timestamp` (DATETIME)

## Authentication

The API uses API key-based authentication:

1. **Registration**: Users register and receive an API key
2. **API Key Usage**: Include `X-API-Key` header in requests
3. **Role Verification**: System checks user role for admin endpoints
4. **Account Status**: Deactivated accounts cannot access API

## Postman Collection

Import the provided `Quotes_API.postman_collection.json` file into Postman for easy testing:

1. Open Postman
2. Click "Import"
3. Select the JSON file
4. The collection includes all endpoints with proper authentication
5. Variables are automatically set for API keys

### Testing Workflow

1. **Health Check** - Verify API is running
2. **Admin Login** - Get admin API key (auto-saved)
3. **Register User** - Create user and get API key (auto-saved)
4. **Add Quotes** - Test quote creation
5. **View Quotes** - Test public access
6. **Admin Functions** - Test user management
7. **Audit Logs** - View system activities

## Error Handling

The API returns consistent JSON responses:

```json
{
  "success": true/false,
  "message": "Description of result",
  "data": {} // Optional data payload
}
```

### Common HTTP Status Codes

- `200` - Success
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (invalid/missing API key)
- `403` - Forbidden (insufficient permissions/deactivated account)
- `404` - Not Found
- `409` - Conflict (duplicate email)
- `500` - Internal Server Error

## Security Features

- **Password Hashing**: bcrypt with default cost
- **API Key Generation**: Cryptographically secure random keys
- **Role-based Access**: Separate user and admin permissions
- **Account Management**: Deactivation/reactivation system
- **Audit Logging**: Complete activity tracking
- **CORS Support**: Cross-origin resource sharing enabled

## Development Tips

### Adding New Endpoints

1. Define handler function
2. Add route in `main()` function
3. Apply appropriate middleware
4. Add audit logging if needed
5. Update Postman collection

### Database Queries

- Use prepared statements (already implemented)
- Handle `sql.ErrNoRows` for not found cases
- Close result sets with `defer rows.Close()`

### Testing

- Use Postman collection for comprehensive testing
- Test both success and error scenarios
- Verify audit logs are created
- Test deactivated user scenarios

## Troubleshooting

### Common Issues

1. **Database locked**: Ensure proper connection closing
2. **Port in use**: Change port in `main()` function
3. **Dependencies**: Run `go mod tidy` to resolve
4. **Permissions**: Ensure write access for SQLite file

### Logs

The application logs:
- Server startup information
- Default admin creation
- Audit activities (in database)
- Error conditions

## Production Considerations

### Security Enhancements
- Use environment variables for sensitive data
- Implement rate limiting
- Add HTTPS/TLS support
- Use stronger password policies
- Implement JWT tokens instead of API keys

### Database
- Consider PostgreSQL for production
- Add database connection pooling
- Implement database migrations
- Add backup strategies

### Monitoring
- Add structured logging
- Implement health checks
- Add metrics collection
- Monitor database performance

## License

This project is provided as-is for educational and development purposes.
