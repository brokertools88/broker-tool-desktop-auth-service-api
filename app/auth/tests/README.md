# InsureCove Authentication Service - Test Cases

This directory contains comprehensive test cases for the authentication service.

## Test Files

### `jwt_generator.py`
- JWT token generation tests
- Token validation tests
- Expiration handling tests
- Security vulnerability tests

## Running Tests

```bash
# Run all authentication tests
python -m pytest app/auth/tests/

# Run specific test file
python -m pytest app/auth/tests/jwt_generator.py

# Run with coverage
python -m pytest --cov=app.auth app/auth/tests/
```

## Test Coverage

The tests cover:
- ✅ JWT token generation and validation
- ✅ Authentication flows
- ✅ Security scenarios
- ✅ Error handling
- ✅ Performance testing 