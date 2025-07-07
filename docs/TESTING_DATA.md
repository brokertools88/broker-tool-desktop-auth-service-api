# 🧪 InsureCove Authentication Service - Testing Data

## 📋 **Mock Testing Data for API Testing**

Use this data to test the InsureCove Authentication Service API endpoints in Swagger UI at `http://localhost:8000/docs`

---

## 👨‍💼 **Broker Test Accounts**

### **Broker Account 1** - Premium Broker
```json
{
  "email": "john.broker@abcinsurance.com",
  "password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Chen",
  "phone_number": "+852-9876-5432",
  "company_name": "ABC Insurance Brokers Ltd",
  "license_number": "BRK123456789",
  "license_expiry": "2025-12-31",
  "company_address": "Suite 1501, Central Plaza, 18 Harbour Road, Hong Kong",
  "business_registration": "BR123456789",
  "website": "https://abcinsurance.com.hk"
}
```

### **Broker Account 2** - Independent Broker
```json
{
  "email": "mary.wong@hongkongbrokers.com",
  "password": "MyStrongPass456!",
  "first_name": "Mary",
  "last_name": "Wong",
  "phone_number": "+852-2345-6789",
  "company_name": "Hong Kong Independent Brokers",
  "license_number": "BRK987654321",
  "license_expiry": "2026-06-30",
  "company_address": "Floor 20, IFC Tower 1, Central, Hong Kong",
  "business_registration": "BR987654321",
  "website": "https://hkbrokers.com"
}
```

### **Broker Account 3** - Startup Broker
```json
{
  "email": "david.lee@innovateinsure.hk",
  "password": "Innovation2024!",
  "first_name": "David",
  "last_name": "Lee",
  "phone_number": "+852-3456-7890",
  "company_name": "Innovate Insurance Solutions",
  "license_number": "BRK555666777",
  "license_expiry": "2025-09-15",
  "company_address": "Unit 888, Cyberport 3, Hong Kong",
  "business_registration": "BR555666777",
  "website": "https://innovateinsure.hk"
}
```

---

## 👥 **Client Test Accounts**

### **Client Account 1** - Young Professional
```json
{
  "email": "alice.chan@email.com",
  "password": "ClientPass123!",
  "first_name": "Alice",
  "last_name": "Chan",
  "phone_number": "+852-9111-2222",
  "date_of_birth": "1992-03-15",
  "hkid_number": "A123456(7)",
  "address": "Flat 15A, Tower 2, Metro City, Tseung Kwan O",
  "occupation": "Software Engineer",
  "annual_income": 600000
}
```

### **Client Account 2** - Family Person
```json
{
  "email": "robert.smith@gmail.com",
  "password": "FamilySecure789!",
  "first_name": "Robert",
  "last_name": "Smith",
  "phone_number": "+852-9333-4444",
  "date_of_birth": "1985-07-22",
  "hkid_number": "B789012(3)",
  "address": "House 12, Discovery Bay, Lantau Island",
  "occupation": "Financial Analyst",
  "annual_income": 850000
}
```

### **Client Account 3** - Senior Executive
```json
{
  "email": "susan.lam@corporate.com",
  "password": "Executive2024!",
  "first_name": "Susan",
  "last_name": "Lam",
  "phone_number": "+852-9555-6666",
  "date_of_birth": "1978-11-08",
  "hkid_number": "C345678(9)",
  "address": "Penthouse A, The Peak Tower, Hong Kong",
  "occupation": "Managing Director",
  "annual_income": 2000000
}
```

---

## 🔐 **Login Test Data**

### **For Testing Login Sessions**
```json
{
  "email": "john.broker@abcinsurance.com",
  "password": "SecurePass123!",
  "remember_me": true
}
```

```json
{
  "email": "alice.chan@email.com",
  "password": "ClientPass123!",
  "remember_me": false
}
```

---

## 🔄 **Token Testing Data**

### **Mock JWT Token for Testing** (if needed)
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### **Token Refresh Request**
```json
{
  "refresh_token": "your-refresh-token-here"
}
```

### **Token Verify Request**
```json
{
  "token": "your-access-token-here"
}
```

---

## 🔑 **Password Management Test Data**

### **Password Change Request**
```json
{
  "current_password": "SecurePass123!",
  "new_password": "NewSecurePass456!",
  "confirm_password": "NewSecurePass456!"
}
```

### **Password Reset Request**
```json
{
  "email": "john.broker@abcinsurance.com"
}
```

### **Password Reset Confirm**
```json
{
  "token": "reset-token-123456",
  "new_password": "ResetPassword789!",
  "confirm_password": "ResetPassword789!"
}
```

---

## 🧪 **Testing Workflow**

### **Step 1: Test Health Endpoints**
1. Go to `http://localhost:8000/docs`
2. Try `GET /health` - Should return service health status
3. Try `GET /api/v1/health/ready` - Should return readiness status

### **Step 2: Create Test Accounts**
1. Use `POST /api/v1/auth/brokers` with Broker Account 1 data
2. Use `POST /api/v1/auth/clients` with Client Account 1 data
3. Check for successful 201 responses

### **Step 3: Test Authentication**
1. Use `POST /api/v1/auth/sessions` with login data
2. Copy the `access_token` from the response
3. Use the token in the "Authorize" button (🔒) in Swagger UI

### **Step 4: Test Protected Endpoints**
1. Use `GET /api/v1/auth/sessions/current` (requires authentication)
2. Try other protected endpoints with the token

### **Step 5: Test Token Management**
1. Use `POST /api/v1/tokens/verify` with your access token
2. Use `POST /api/v1/tokens/refresh` with your refresh token

### **Step 6: Test Metrics**
1. Try `GET /api/v1/metrics` for detailed metrics
2. Try `GET /api/v1/metrics/summary` for summary
3. Try `GET /api/v1/metrics/auth` for auth-specific metrics

---

## ⚠️ **Important Notes for Local Testing**

### **Expected Limitations in Proxy Environment:**
- ✅ **Health checks** will work
- ✅ **User registration** will work (stored locally in memory)
- ✅ **Login attempts** will work with mock authentication
- ❌ **JWT token generation** may fail (requires AWS Secrets Manager)
- ❌ **Token verification** may fail (no secret key access)
- ❌ **Supabase operations** may fail (network restrictions)

### **Workarounds for Testing:**
1. **Mock Mode**: The service should fallback to mock authentication
2. **Health Endpoints**: Always available for testing
3. **Metrics Endpoints**: Should work for basic system info
4. **API Structure**: All endpoints will show correct request/response formats

---

## 🎯 **Quick Test Commands (cURL)**

### **Health Check**
```bash
curl http://localhost:8000/api/v1/health
```

### **Create Broker**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/brokers" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.broker@abcinsurance.com",
    "password": "SecurePass123!",
    "first_name": "John",
    "last_name": "Chen",
    "company_name": "ABC Insurance Brokers Ltd",
    "license_number": "BRK123456789"
  }'
```

### **Login**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/sessions" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.broker@abcinsurance.com",
    "password": "SecurePass123!"
  }'
```

### **Get Metrics**
```bash
curl http://localhost:8000/api/v1/metrics/summary
```

---

## 🚀 **Pro Tips for API Testing**

1. **Use Swagger UI**: Much easier than cURL for complex requests
2. **Start Simple**: Begin with health endpoints, then registration
3. **Copy Tokens**: Save access tokens for testing protected endpoints
4. **Check Responses**: Look at the response schemas and examples
5. **Test Error Cases**: Try invalid data to see error handling
6. **Monitor Logs**: Check the terminal for request logs and errors

---

**Happy Testing! 🧪✨**

*Last Updated: January 15, 2024*
