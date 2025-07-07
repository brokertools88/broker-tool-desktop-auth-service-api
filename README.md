# 🔐 InsureCove Authentication Service

A production-ready FastAPI authentication service following 2024 REST API standards with Supabase integration, AWS Secrets Manager, and comprehensive monitoring.

## 🚀 Features

- **FastAPI Framework** - Modern, fast, and type-safe API development
- **Supabase Integration** - Secure user authentication and management
- **AWS Secrets Manager** - Production-grade secret management
- **JWT Authentication** - Stateless token-based authentication
- **Rate Limiting** - Request throttling with Redis
- **Health Checks** - Kubernetes-compatible health monitoring
- **Metrics Collection** - Prometheus metrics integration
- **RFC 9457 Compliance** - Standardized error responses
- **Docker Support** - Production-ready containerization
- **Comprehensive Testing** - Unit, integration, and performance tests

## 📋 Requirements

- Python 3.11+
- Redis (for rate limiting)
- AWS Account (for secrets management)
- Supabase Account (for authentication)

## 🛠️ Installation

### Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd broker-tool-desktop-auth-service-api
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

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Run the application**
   ```bash
   python -m app.main
   ```

### Docker Setup

1. **Build and run with Docker Compose**
   ```bash
   docker-compose up -d
   ```

2. **Access the services**
   - API: http://localhost:8000
   - Documentation: http://localhost:8000/docs
   - Metrics: http://localhost:8000/metrics
   - Grafana: http://localhost:3000

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Application secret key | Required |
| `SUPABASE_URL` | Supabase project URL | Required |
| `SUPABASE_ANON_KEY` | Supabase anonymous key | Required |
| `SUPABASE_SERVICE_KEY` | Supabase service key | Required |
| `AWS_REGION` | AWS region | `ap-southeast-1` |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `RATE_LIMIT_REQUESTS` | Requests per minute | `100` |
| `ENVIRONMENT` | Application environment | `development` |
| `DEBUG` | Debug mode | `true` |

## 📚 API Documentation

### Authentication Endpoints

- `POST /auth/brokers` - Create broker account
- `POST /auth/clients` - Create client account
- `POST /auth/sessions` - Login user
- `GET /auth/sessions/current` - Get current session
- `POST /auth/tokens/refresh` - Refresh JWT token
- `POST /auth/tokens/verify` - Verify JWT token

### Health & Monitoring

- `GET /health` - Detailed health check
- `GET /health/ready` - Readiness probe
- `GET /health/live` - Liveness probe
- `GET /metrics` - Prometheus metrics

### Example Usage

```bash
# Register a new broker
curl -X POST http://localhost:8000/auth/brokers \
  -H "Content-Type: application/json" \
  -d '{
    "email": "broker@example.com",
    "password": "securepassword123",
    "company_name": "Example Insurance",
    "license_number": "BR123456"
  }'

# Login
curl -X POST http://localhost:8000/auth/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "email": "broker@example.com",
    "password": "securepassword123"
  }'
```

## 🧪 Testing

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=app

# Run specific test file
python -m pytest app/auth/tests/jwt_generator.py

# Run performance tests
python -m pytest tests/performance/
```

## 🚀 Deployment

### Production Deployment

1. **Build production image**
   ```bash
   docker build -t insurecove-auth-service .
   ```

2. **Run with production settings**
   ```bash
   docker run -p 8000:8000 \
     -e ENVIRONMENT=production \
     -e DEBUG=false \
     --env-file .env \
     insurecove-auth-service
   ```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insurecove-auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: insurecove-auth-service
  template:
    metadata:
      labels:
        app: insurecove-auth-service
    spec:
      containers:
      - name: auth-service
        image: insurecove-auth-service:latest
        ports:
        - containerPort: 8000
        env:
        - name: ENVIRONMENT
          value: "production"
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8000
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8000
```

## 📊 Monitoring

### Metrics

The service exposes metrics in Prometheus format:

- Request count and latency
- Authentication success/failure rates
- Database connection health
- Redis connection health
- System resource usage

### Health Checks

- `/health` - Comprehensive health check
- `/health/ready` - Readiness probe for K8s
- `/health/live` - Liveness probe for K8s

## 🔐 Security

- **JWT Authentication** - Stateless token-based auth
- **Rate Limiting** - Prevent abuse and DoS attacks
- **CORS Protection** - Cross-origin request filtering
- **Input Validation** - Pydantic model validation
- **Secret Management** - AWS Secrets Manager integration
- **Non-root Container** - Security-hardened Docker image

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the [documentation](docs/)
- Review the [troubleshooting guide](docs/troubleshooting.md)

## 🏗️ Project Structure

```
broker-tool-desktop-auth-service-api/
├── app/                    # Main application code
│   ├── main.py            # FastAPI application entry point
│   ├── core/              # Core utilities and config
│   ├── api/               # API route modules
│   └── auth/              # Authentication logic
├── docs/                  # Documentation
├── monitoring/            # Monitoring configuration
├── tests/                 # Test suites
├── scripts/               # Deployment scripts
├── requirements.txt       # Python dependencies
├── Dockerfile            # Container configuration
└── docker-compose.yml    # Development environment
```

---

**Built with ❤️ for InsureCove** 