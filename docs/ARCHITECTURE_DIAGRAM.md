# 🏛️ InsureCove Authentication Service - Architecture Diagram

## 🎯 **System Architecture Overview**

```mermaid
graph TB
    %% External Systems
    Client[Client Applications<br/>Web/Mobile/Desktop]
    LoadBalancer[Load Balancer<br/>nginx/AWS ALB]
    
    %% Main Service
    subgraph "Authentication Service"
        FastAPI[FastAPI Application<br/>main.py]
        
        subgraph "API Layer"
            AuthRoutes[Authentication Routes<br/>auth_routes.py]
            HealthRoutes[Health Routes<br/>health_routes.py]
            MetricsRoutes[Metrics Routes<br/>metrics_routes.py]
        end
        
        subgraph "Core Layer"
            Config[Configuration<br/>config.py]
            Security[Security & JWT<br/>security.py]
            Exceptions[Exception Handling<br/>exceptions.py]
            Logging[Logging Config<br/>logging_config.py]
        end
        
        subgraph "Auth Layer"
            AuthAdapter[Auth Adapter<br/>auth_adapter.py]
            SupabaseAuth[Supabase Manager<br/>supabase_auth.py]
            AWSSecrets[AWS Secrets<br/>aws_secrets.py]
        end
        
        subgraph "Models"
            APIModels[API Models<br/>models.py]
        end
    end
    
    %% External Services
    subgraph "External Services"
        Supabase[(Supabase<br/>Authentication DB)]
        AWSSecretsManager[(AWS Secrets Manager<br/>JWT Keys & Secrets)]
        Redis[(Redis<br/>Rate Limiting & Cache)]
    end
    
    %% Monitoring
    subgraph "Monitoring & Observability"
        Prometheus[Prometheus<br/>Metrics Collection]
        Grafana[Grafana<br/>Dashboards]
        CloudWatch[AWS CloudWatch<br/>Logs & Monitoring]
    end
    
    %% Client Flow
    Client --> LoadBalancer
    LoadBalancer --> FastAPI
    
    %% API Flow
    FastAPI --> AuthRoutes
    FastAPI --> HealthRoutes
    FastAPI --> MetricsRoutes
    
    %% Route Dependencies
    AuthRoutes --> AuthAdapter
    AuthRoutes --> Security
    AuthRoutes --> APIModels
    
    HealthRoutes --> Config
    HealthRoutes --> APIModels
    
    MetricsRoutes --> Config
    MetricsRoutes --> APIModels
    
    %% Core Dependencies
    AuthAdapter --> SupabaseAuth
    Security --> AWSSecrets
    Config --> AWSSecrets
    
    %% External Connections
    SupabaseAuth --> Supabase
    AWSSecrets --> AWSSecretsManager
    Security --> Redis
    
    %% Monitoring Connections
    FastAPI --> Prometheus
    Prometheus --> Grafana
    Logging --> CloudWatch
    
    %% Error Handling
    AuthRoutes --> Exceptions
    HealthRoutes --> Exceptions
    MetricsRoutes --> Exceptions
    
    %% Styling
    classDef clientClass fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    classDef serviceClass fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef coreClass fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    classDef authClass fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef externalClass fill:#fce4ec,stroke:#c2185b,stroke-width:2px
    classDef monitoringClass fill:#e0f2f1,stroke:#00695c,stroke-width:2px
    
    class Client,LoadBalancer clientClass
    class FastAPI,AuthRoutes,HealthRoutes,MetricsRoutes,APIModels serviceClass
    class Config,Security,Exceptions,Logging coreClass
    class AuthAdapter,SupabaseAuth,AWSSecrets authClass
    class Supabase,AWSSecretsManager,Redis externalClass
    class Prometheus,Grafana,CloudWatch monitoringClass
```

---

## 🔄 **Request Flow Diagram**

```mermaid
sequenceDiagram
    participant C as Client
    participant LB as Load Balancer
    participant API as FastAPI App
    participant AR as Auth Routes
    participant AA as Auth Adapter
    participant SA as Supabase Auth
    participant AWS as AWS Secrets
    participant SB as Supabase DB
    participant R as Redis Cache
    
    Note over C,R: User Registration Flow
    
    C->>LB: POST /auth/brokers
    LB->>API: Forward request
    API->>AR: Route to auth handler
    AR->>AA: create_broker(data)
    AA->>SA: register_user(data)
    SA->>SB: Create user record
    SB-->>SA: User created
    SA-->>AA: User response
    AA-->>AR: Formatted response
    AR-->>API: HTTP 201 response
    API-->>LB: Return response
    LB-->>C: User created successfully
    
    Note over C,R: Login Flow
    
    C->>LB: POST /auth/sessions
    LB->>API: Forward login request
    API->>AR: Route to login handler
    AR->>AA: authenticate(credentials)
    AA->>SA: login_user(email, password)
    SA->>SB: Verify credentials
    SB-->>SA: User verified
    SA->>AWS: Get JWT signing key
    AWS-->>SA: Return secret
    SA->>SA: Generate JWT tokens
    SA->>R: Store session data
    SA-->>AA: Return tokens + user
    AA-->>AR: Formatted response
    AR-->>API: HTTP 200 response
    API-->>LB: Return tokens
    LB-->>C: Login successful
    
    Note over C,R: Protected Request Flow
    
    C->>LB: GET /auth/sessions/current
    LB->>API: Forward with Bearer token
    API->>AR: Route to session handler
    AR->>AA: get_current_session(token)
    AA->>SA: verify_token(token)
    SA->>AWS: Get JWT verification key
    AWS-->>SA: Return public key
    SA->>SA: Verify token signature
    SA->>R: Check session cache
    R-->>SA: Session data
    SA-->>AA: Current user data
    AA-->>AR: Formatted response
    AR-->>API: HTTP 200 response
    API-->>LB: Return user data
    LB-->>C: Current session info
```

---

## 🏗️ **Component Architecture**

```mermaid
graph LR
    subgraph "Client Layer"
        WebApp[Web Application]
        MobileApp[Mobile App]
        Desktop[Desktop App]
    end
    
    subgraph "API Gateway"
        Gateway[API Gateway/Load Balancer]
        RateLimit[Rate Limiting]
        CORS[CORS Middleware]
    end
    
    subgraph "Authentication Service"
        subgraph "Presentation Layer"
            REST[REST API Endpoints]
            OpenAPI[OpenAPI/Swagger]
            Validation[Request Validation]
        end
        
        subgraph "Business Logic Layer"
            AuthLogic[Authentication Logic]
            UserMgmt[User Management]
            TokenMgmt[Token Management]
            PasswordMgmt[Password Management]
        end
        
        subgraph "Data Access Layer"
            SupabaseClient[Supabase Client]
            AWSClient[AWS Secrets Client]
            CacheClient[Redis Client]
        end
        
        subgraph "Cross-Cutting Concerns"
            ErrorHandling[Error Handling]
            Logging[Logging]
            Monitoring[Monitoring]
            Security[Security]
        end
    end
    
    subgraph "External Services"
        SupabaseDB[(Supabase Database)]
        AWSSecrets[(AWS Secrets Manager)]
        RedisCache[(Redis Cache)]
    end
    
    subgraph "Monitoring Stack"
        Metrics[Metrics Collection]
        LogAggregation[Log Aggregation]
        Alerting[Alerting]
    end
    
    %% Client connections
    WebApp --> Gateway
    MobileApp --> Gateway
    Desktop --> Gateway
    
    %% Gateway to Service
    Gateway --> REST
    RateLimit --> REST
    CORS --> REST
    
    %% API Layer connections
    REST --> AuthLogic
    REST --> Validation
    Validation --> OpenAPI
    
    %% Business Logic connections
    AuthLogic --> UserMgmt
    AuthLogic --> TokenMgmt
    AuthLogic --> PasswordMgmt
    
    %% Data Access connections
    UserMgmt --> SupabaseClient
    TokenMgmt --> AWSClient
    TokenMgmt --> CacheClient
    
    %% External Service connections
    SupabaseClient --> SupabaseDB
    AWSClient --> AWSSecrets
    CacheClient --> RedisCache
    
    %% Cross-cutting connections
    REST --> ErrorHandling
    AuthLogic --> Logging
    TokenMgmt --> Monitoring
    UserMgmt --> Security
    
    %% Monitoring connections
    Logging --> LogAggregation
    Monitoring --> Metrics
    ErrorHandling --> Alerting
    
    %% Styling
    classDef clientLayer fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef gatewayLayer fill:#f1f8e9,stroke:#689f38,stroke-width:2px
    classDef serviceLayer fill:#fce4ec,stroke:#ad1457,stroke-width:2px
    classDef dataLayer fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef externalLayer fill:#e8eaf6,stroke:#5e35b1,stroke-width:2px
    classDef monitoringLayer fill:#e0f2f1,stroke:#00695c,stroke-width:2px
    
    class WebApp,MobileApp,Desktop clientLayer
    class Gateway,RateLimit,CORS gatewayLayer
    class REST,OpenAPI,Validation,AuthLogic,UserMgmt,TokenMgmt,PasswordMgmt serviceLayer
    class SupabaseClient,AWSClient,CacheClient dataLayer
    class SupabaseDB,AWSSecrets,RedisCache externalLayer
    class Metrics,LogAggregation,Alerting,ErrorHandling,Logging,Monitoring,Security monitoringLayer
```

---

## 🚀 **Deployment Architecture**

```mermaid
graph TB
    subgraph "Production Environment"
        subgraph "Load Balancer"
            ALB[AWS Application Load Balancer]
            SSL[SSL Termination]
        end
        
        subgraph "Container Orchestration"
            ECS[AWS ECS/Fargate]
            subgraph "Service Instances"
                Container1[Auth Service Instance 1]
                Container2[Auth Service Instance 2]
                Container3[Auth Service Instance 3]
            end
        end
        
        subgraph "Caching Layer"
            ElastiCache[AWS ElastiCache<br/>Redis Cluster]
        end
        
        subgraph "External Services"
            SupabaseCloud[Supabase Cloud<br/>Managed Database]
            SecretsManager[AWS Secrets Manager<br/>Encrypted Secrets]
        end
        
        subgraph "Monitoring & Logging"
            CloudWatch[AWS CloudWatch<br/>Logs & Metrics]
            XRay[AWS X-Ray<br/>Distributed Tracing]
        end
        
        subgraph "Security"
            WAF[AWS WAF<br/>Web Application Firewall]
            VPC[VPC with Private Subnets]
            IAM[IAM Roles & Policies]
        end
    end
    
    subgraph "Development Environment"
        LocalDev[Local Development<br/>Docker Compose]
        LocalRedis[Local Redis]
        LocalSupabase[Local Supabase]
    end
    
    subgraph "CI/CD Pipeline"
        GitHub[GitHub Repository]
        Actions[GitHub Actions]
        ECR[AWS ECR<br/>Container Registry]
    end
    
    %% Production Flow
    Internet --> WAF
    WAF --> ALB
    SSL --> ALB
    ALB --> ECS
    ECS --> Container1
    ECS --> Container2
    ECS --> Container3
    
    %% Service Dependencies
    Container1 --> ElastiCache
    Container2 --> ElastiCache
    Container3 --> ElastiCache
    
    Container1 --> SupabaseCloud
    Container2 --> SupabaseCloud
    Container3 --> SupabaseCloud
    
    Container1 --> SecretsManager
    Container2 --> SecretsManager
    Container3 --> SecretsManager
    
    %% Monitoring
    Container1 --> CloudWatch
    Container2 --> CloudWatch
    Container3 --> CloudWatch
    
    Container1 --> XRay
    Container2 --> XRay
    Container3 --> XRay
    
    %% Security
    ECS --> VPC
    ECS --> IAM
    
    %% Development
    LocalDev --> LocalRedis
    LocalDev --> LocalSupabase
    
    %% CI/CD
    GitHub --> Actions
    Actions --> ECR
    ECR --> ECS
    
    %% Styling
    classDef prodClass fill:#ffebee,stroke:#c62828,stroke-width:2px
    classDef devClass fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef cicdClass fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    classDef securityClass fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    classDef monitoringClass fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px
    
    class ALB,SSL,ECS,Container1,Container2,Container3,ElastiCache,SupabaseCloud,SecretsManager prodClass
    class LocalDev,LocalRedis,LocalSupabase devClass
    class GitHub,Actions,ECR cicdClass
    class WAF,VPC,IAM securityClass
    class CloudWatch,XRay monitoringClass
```

---

## 📊 **Data Flow Architecture**

```mermaid
graph LR
    subgraph "Data Sources"
        UserInput[User Input<br/>Registration/Login]
        ConfigData[Configuration<br/>Environment Variables]
        SecretData[Secret Data<br/>AWS Secrets Manager]
    end
    
    subgraph "Processing Layers"
        Validation[Data Validation<br/>Pydantic Models]
        Transformation[Data Transformation<br/>Business Logic]
        Security[Security Processing<br/>Hashing/Encryption]
    end
    
    subgraph "Storage Layers"
        UserDB[(User Database<br/>Supabase)]
        SessionCache[(Session Cache<br/>Redis)]
        Secrets[(Secrets Storage<br/>AWS Secrets Manager)]
        Logs[(Log Storage<br/>CloudWatch)]
    end
    
    subgraph "Output Formats"
        JSONResponse[JSON API Response]
        JWTToken[JWT Tokens]
        Metrics[Metrics Data]
        LogEntries[Structured Logs]
    end
    
    %% Input Flow
    UserInput --> Validation
    ConfigData --> Validation
    SecretData --> Security
    
    %% Processing Flow
    Validation --> Transformation
    Transformation --> Security
    
    %% Storage Flow
    Security --> UserDB
    Transformation --> SessionCache
    Security --> Secrets
    Transformation --> Logs
    
    %% Output Flow
    UserDB --> JSONResponse
    Security --> JWTToken
    SessionCache --> Metrics
    Logs --> LogEntries
    
    %% Styling
    classDef inputClass fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    classDef processClass fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef storageClass fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef outputClass fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    
    class UserInput,ConfigData,SecretData inputClass
    class Validation,Transformation,Security processClass
    class UserDB,SessionCache,Secrets,Logs storageClass
    class JSONResponse,JWTToken,Metrics,LogEntries outputClass
```

---

## 🔧 **Technical Stack Overview**

```mermaid
mindmap
  root((InsureCove Auth Service))
    Framework
      FastAPI
      Pydantic v2
      Python 3.11+
      uvicorn
    Authentication
      Supabase Auth
      JWT Tokens
      bcrypt Hashing
      OAuth 2.0
    Storage
      Supabase PostgreSQL
      Redis Cache
      AWS Secrets Manager
      CloudWatch Logs
    Security
      HTTPS/TLS
      CORS Protection
      Rate Limiting
      Input Validation
    Monitoring
      Health Checks
      Metrics Collection
      Structured Logging
      Error Tracking
    Deployment
      Docker Containers
      AWS ECS/Fargate
      Application Load Balancer
      Auto Scaling
    Development
      GitHub Repository
      GitHub Actions CI/CD
      Docker Compose
      Environment Config
```

---

## 🎯 **Key Architectural Decisions**

### **1. Layered Architecture**
- **Presentation Layer**: FastAPI routes and API models
- **Business Logic Layer**: Authentication and user management
- **Data Access Layer**: Supabase and AWS integrations
- **Cross-Cutting Concerns**: Logging, monitoring, security

### **2. External Service Integration**
- **Supabase**: Primary authentication and user data storage
- **AWS Secrets Manager**: Secure secret and JWT key management
- **Redis**: Session caching and rate limiting

### **3. Security-First Design**
- JWT tokens with RS256 signing
- Secure secret management (no hardcoded secrets)
- Rate limiting and CORS protection
- Input validation and sanitization

### **4. Observability**
- Structured logging with correlation IDs
- Health checks for all dependencies
- Comprehensive metrics collection
- Error tracking and alerting

### **5. Scalability**
- Stateless service design
- Horizontal scaling capability
- Load balancer distribution
- Cache-first data access patterns

---

**Last Updated**: January 15, 2024  
**Architecture Version**: 1.0.0
