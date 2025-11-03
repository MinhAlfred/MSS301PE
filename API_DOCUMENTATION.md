# API Documentation for Frontend Developer

## Base Configuration

**API Gateway URL:** `http://localhost:4000`

All API requests should be made through the API Gateway on port 4000. The gateway will route requests to the appropriate microservices:
- Account Service: port 8081
- Brand Service: port 8082
- BlindBox Service: port 8080

---

## Standard API Response Format

All API endpoints return a standardized response format:

```json
{
  "success": true/false,
  "message": "Optional message",
  "data": {}, // Response data (can be null)
  "timestamp": "2025-11-03T10:30:00Z"
}
```

---

## Authentication Service

### 1. Login

**Endpoint:** `POST /api/auth/login`

**Description:** Authenticate user and receive JWT token

**Request Headers:**
```
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Validation Rules:**
- `email`: Required, must be valid email format
- `password`: Required, cannot be blank

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Login success",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "accountId": 1,
    "email": "user@example.com",
    "role": 1
  },
  "timestamp": "2025-11-03T10:30:00Z"
}
```

**Role Values:**
- `1`: Administrator
- `2`: Moderator
- `3`: Developer
- `4`: Member

**Error Response (4xx):**
```json
{
  "success": false,
  "message": "Invalid credentials",
  "data": null,
  "timestamp": "2025-11-03T10:30:00Z"
}
```

**Usage Notes:**
- Store the `token` from the response for authenticated requests
- Use the `role` value to determine user permissions
- Token expires after 1 hour (3600000ms)

---

## Blind Box Service

### 6. Get All Blind Boxes

**Endpoint:** `GET /api/blindboxes/all`

**Description:** Retrieve all blind boxes with their details

**Request Headers:** None required

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": null,
  "data": [
    {
      "blindBoxId": 1,
      "name": "Blind Box Name",
      "categoryName": "Category Name",
      "brandName": "Brand Name",
      "price": 29.99,
      "releaseDate": "2025-11-15",
      "stock": 50
    }
  ],
  "timestamp": "2025-11-03T10:30:00Z"
}
```

### 7. Create Blind Box (BlindBox Service) - ADMIN ONLY

**Endpoint:** `POST /api/blindboxes/create`

**Description:** Create a new blind box (requires ADMIN role)

**Request Headers:**
```
Content-Type: application/json
X-USER-ROLE: 1
```

**Request Body:**
```json
{
  "name": "New Blind Box Name (min 10 chars)",
  "categoryId": 1,
  "brandId": 1,
  "price": 29.99,
  "stock": 50,
  "releaseDate": "2025-11-15"
}
```

**Validation Rules:**
- `name`: Required, minimum 10 characters
- `categoryId`: Required, must be valid integer
- `brandId`: Required, must be valid integer
- `price`: Required, must be greater than 0
- `stock`: Required, minimum 1, maximum 100
- `releaseDate`: Required, format: "YYYY-MM-DD"

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Blind box created successfully",
  "data": {
    "blindBoxId": 1,
    "name": "New Blind Box Name",
    "categoryName": "Category Name",
    "brandName": "Brand Name",
    "price": 29.99,
    "releaseDate": "2025-11-15",
    "stock": 50
  },
  "timestamp": "2025-11-03T10:30:00Z"
}
```

**Access Denied Response (200 OK with error):**
```json
{
  "success": false,
  "message": "Access denied: ADMIN only",
  "data": null,
  "timestamp": "2025-11-03T10:30:00Z"
}
```

### 8. Update Blind Box (BlindBox Service) - ADMIN ONLY

**Endpoint:** `PUT /api/blindboxes/update/{id}`

**Description:** Update an existing blind box (requires ADMIN role)

**Path Parameters:**
- `id`: Integer - Blind Box ID

**Request Headers:**
```
Content-Type: application/json
X-USER-ROLE: 1
```

**Request Body:**
```json
{
  "name": "Updated Blind Box Name (min 10 chars)",
  "categoryId": 1,
  "brandId": 1,
  "price": 35.99,
  "stock": 75,
  "releaseDate": "2025-11-20"
}
```

**Validation Rules:** Same as Create endpoint

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Blind box updated successfully",
  "data": {
    "blindBoxId": 1,
    "name": "Updated Blind Box Name",
    "categoryName": "Category Name",
    "brandName": "Brand Name",
    "price": 35.99,
    "releaseDate": "2025-11-20",
    "stock": 75
  },
  "timestamp": "2025-11-03T10:30:00Z"
}
```

### 9. Delete Blind Box (BlindBox Service) - ADMIN ONLY

**Endpoint:** `DELETE /api/blindboxes/delete/{id}`

**Description:** Delete a blind box by ID (requires ADMIN role)

**Path Parameters:**
- `id`: Integer - Blind Box ID

**Request Headers:**
```
X-USER-ROLE: 1
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Blind box deleted successfully",
  "data": null,
  "timestamp": "2025-11-03T10:30:00Z"
}
```

**Access Denied Response (200 OK with error):**
```json
{
  "success": false,
  "message": "Access denied: ADMIN only",
  "data": null,
  "timestamp": "2025-11-03T10:30:00Z"
}
```

---

## Authorization

### JWT Token Usage

After successful login, include the JWT token in subsequent requests:

```
Authorization: Bearer {token}
```

### Role-Based Access Control

Some endpoints require the `X-USER-ROLE` header:

- **Role 1 (ADMIN)**: Full access to create, update, and delete operations
- **Role 2 (USER)**: Read-only access

**IMPORTANT:** For BlindBox Service endpoints that require ADMIN access:
- You must include `X-USER-ROLE: 1` in the request header
- If the role is not "1", you will receive an "Access denied: ADMIN only" error

---

## Error Handling

### Common Error Responses

**Validation Error (400 Bad Request):**
```json
{
  "success": false,
  "message": "Validation error details",
  "data": null,
  "timestamp": "2025-11-03T10:30:00Z"
}
```

**Unauthorized (401):**
```json
{
  "success": false,
  "message": "Unauthorized access",
  "data": null,
  "timestamp": "2025-11-03T10:30:00Z"
}
```

**Not Found (404):**
```json
{
  "success": false,
  "message": "Resource not found",
  "data": null,
  "timestamp": "2025-11-03T10:30:00Z"
}
```

**Server Error (500):**
```json
{
  "success": false,
  "message": "Internal server error",
  "data": null,
  "timestamp": "2025-11-03T10:30:00Z"
}
```

---

## Quick Reference

### Service Ports (Direct Access)
- API Gateway: `http://localhost:4000`
- Account Service: `http://localhost:8081`
- Brand Service: `http://localhost:8082`
- BlindBox Service: `http://localhost:8080`

### Recommended Usage
Always use the API Gateway URL (`http://localhost:4000`) for all requests. The gateway handles routing automatically.

### Authentication Flow
1. Call `POST /api/auth/login` with credentials
2. Store the returned `token` and `role`
3. Include `Authorization: Bearer {token}` in subsequent requests
4. For ADMIN operations, also include `X-USER-ROLE: 1` header

### Field Formats
- **Date:** ISO 8601 format `YYYY-MM-DD`
- **Decimal:** Use decimal notation (e.g., `29.99`)
- **Email:** Valid email format (e.g., `user@example.com`)
- **Timestamp:** ISO 8601 format with timezone (e.g., `2025-11-03T10:30:00Z`)

---

## Notes for Frontend Developer

1. **Always check the `success` field** in the response before processing data
2. **Handle validation errors** by displaying the `message` field to users
3. **Store JWT token securely** (localStorage or sessionStorage)
4. **Implement role-based UI** based on the user's role from login response
5. **Handle token expiration** (1 hour) by prompting re-login
6. **All requests go through API Gateway** on port 4000
7. **Date format** for requests must be `YYYY-MM-DD` (LocalDate format)
8. **Price values** should be sent as numbers with decimal precision
