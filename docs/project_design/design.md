# Insurance Renewal Management System - Design Document

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture Design](#architecture-design)
3. [API Design Standards](#api-design-standards)
4. [Security Design](#security-design)
5. [Database Design](#database-design)
6. [Implementation Guidelines](#implementation-guidelines)

## System Overview

### Project Description
Insurance renewal management system designed to remind clients and brokers about upcoming policy renewals, automating and simplifying the process of managing policy renewals and amendments.

### Core Functions
1. **Automated Renewal Reminders**: Proactive policy management with smart notifications
2. **Policy Details Management**: Comprehensive policy information retrieval and viewing
3. **Renewal Communication**: Streamlined broker-client-underwriter communication
4. **Policy Amendments**: Support for policy changes and endorsements
5. **OCR Document Processing**: AI-powered document extraction and processing
6. **Database Management**: Centralized record keeping and data management

### Current System Analysis
- **Existing Database**: Supabase PostgreSQL with comprehensive schema and RLS policies
- **Current Workflows**: n8n-based automation transitioning to AI agents
- **AI Integration**: Mistral AI and X.AI Grok for intelligent processing and OCR
- **API Architecture**: Microservices with FastAPI transitioning from webhook-based endpoints
- **Frontend**: TypeScript React application with real-time Supabase integration

## Architecture Design

### High-Level Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │    │ TypeScript Web  │    │  Mobile Apps    │
│   (External)    │    │ Frontend (React)│    │   (Future)      │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼──────────────┐
                    │   Supabase API Gateway     │
                    │  (Auth/RLS/Real-time)      │
                    └─────────────┬──────────────┘
                                 │
                    ┌─────────────▼──────────────┐
                    │  Python Microservices      │
                    │    (FastAPI + AI Agents)   │
                    └─────────────┬──────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
┌─────────▼─────────┐  ┌─────────▼─────────┐  ┌─────────▼─────────┐
│  Supabase Data    │  │    AI Agents      │  │  External APIs    │
│  (PostgreSQL+RLS) │  │ (Mistral/Grok)    │  │ (Email/SMS/etc)   │
└───────────────────┘  └───────────────────┘  └───────────────────┘
          │                      │                      │
┌─────────▼─────────┐  ┌─────────▼─────────┐  ┌─────────▼─────────┐
│  Hybrid Storage   │  │ Real-time Updates │  │ HK Integrations   │
│ (Supabase+AWS S3) │  │   & Analytics     │  │ (HKMA/Insurers)   │
└───────────────────┘  └───────────────────┘  └───────────────────┘
```

## Design Pattern Architecture

### Three-Level Design Pattern Strategy

This system employs a **Three-Level Design Pattern Architecture** that combines the benefits of microservices at the system level, familiar Model-Controller patterns within each service, and intelligent AI agents for data processing.

#### Level 1: System Architecture - Microservices Pattern
```
┌─────────────────────────────────────────────────────────────────┐
│                     MICROSERVICES LEVEL                        │
├─────────────┬─────────────┬─────────────┬─────────────────────┤
│ Auth Service│Client Service│Policy Service│Document Service     │
│   :8001     │    :8002    │    :8003    │      :8004         │
└─────────────┴─────────────┴─────────────┴─────────────────────┘
      │              │              │              │
      ▼              ▼              ▼              ▼
```

#### Level 2: Service Architecture - Model-Controller Pattern
```
┌─────────────────────────────────────────────────────────────────┐
│              MODEL-CONTROLLER LEVEL (within each service)       │
│┌───────────────┐┌───────────────┐┌───────────────┐┌────────────┐│
││   SERVICE 1   ││   SERVICE 2   ││   SERVICE 3   ││ SERVICE 4  ││
││┌─────────────┐││┌─────────────┐││┌─────────────┐││┌──────────┐││
│││Controllers  │││Controllers  │││Controllers  │││Controllers││
│││     │       │││     │       │││     │       │││    │     ││
│││     ▼       │││     ▼       │││     ▼       │││    ▼     ││
│││  Services   │││  Services   │││  Services   │││ Services ││
│││     │       │││     │       │││     │       │││    │     ││
│││     ▼       │││     ▼       │││     ▼       │││    ▼     ││
│││  Models     │││  Models     │││  Models     │││  Models  ││
│││     │       │││     │       │││     │       │││    │     ││
│││     ▼       │││     ▼       │││     ▼       │││    ▼     ││
│││Repository   │││Repository   │││Repository   │││Repository││
││└─────────────┘││└─────────────┘││└─────────────┘││└──────────┘││
│└───────────────┘└───────────────┘└───────────────┘└────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  Shared Database │
                    │   (Supabase)     │
                    └─────────────────┘
```

### Service-Level Architecture Pattern

Each microservice follows a clean **Model-Controller (MC)** pattern without Views (since these are API-only services):

#### Architecture Layers Within Each Service:
```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT SERVICE EXAMPLE                   │
├─────────────────────────────────────────────────────────────┤
│  Controllers Layer (HTTP Handling)                         │
│  ├── client_controller.py    (REST endpoints)              │
│  ├── health_controller.py    (health checks)               │
│  └── middleware.py           (request/response processing)  │
├─────────────────────────────────────────────────────────────┤
│  Services Layer (Business Logic)                           │
│  ├── client_service.py       (business operations)         │
│  ├── validation_service.py   (business validation)         │
│  └── analytics_service.py    (client analytics)            │
├─────────────────────────────────────────────────────────────┤
│  Models Layer (Data & Domain Logic)                        │
│  ├── client_model.py         (Pydantic models)             │
│  ├── schemas.py              (request/response schemas)     │
│  └── repository.py           (data access layer)           │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure Layer                                       │
│  ├── database.py             (Supabase connection)         │
│  ├── config.py               (service configuration)       │
│  └── dependencies.py         (dependency injection)        │
└─────────────────────────────────────────────────────────────┘
```

### Benefits of This Hybrid Approach

#### System-Level Benefits (Microservices):
- **Scalability**: Scale individual services based on demand
- **Technology Flexibility**: Choose optimal tech stack per service
- **Fault Isolation**: Service failures don't cascade
- **Team Independence**: Teams can work on services independently
- **Deployment Flexibility**: Deploy services independently

#### Service-Level Benefits (Model-Controller):
- **Familiar Pattern**: Most developers know MVC concepts
- **Clear Structure**: Easy to onboard new developers
- **Testable**: Each layer can be tested independently
- **Maintainable**: Clear separation of concerns
- **Reusable**: Business logic separated from HTTP handling

### Implementation Structure Example

#### Directory Structure Per Service:
```
client-service/
├── app/
│   ├── controllers/              # 🎯 Controller Layer
│   │   ├── __init__.py
│   │   ├── client_controller.py  # HTTP request handling
│   │   └── health_controller.py  # Service health endpoints
│   ├── services/                 # 🧠 Business Logic Layer
│   │   ├── __init__.py
│   │   ├── client_service.py     # Core business operations
│   │   ├── validation_service.py # Business validation rules
│   │   └── analytics_service.py  # Client analytics
│   ├── models/                   # 📊 Data Layer
│   │   ├── __init__.py
│   │   ├── client_model.py       # Pydantic data models
│   │   ├── schemas.py            # Request/response schemas
│   │   └── repository.py         # Data access patterns
│   ├── infrastructure/           # 🔧 Infrastructure Layer
│   │   ├── __init__.py
│   │   ├── database.py           # Supabase client setup
│   │   ├── config.py             # Service configuration
│   │   └── dependencies.py       # Dependency injection
│   └── main.py                   # FastAPI app initialization
├── tests/
│   ├── test_controllers/         # Controller tests
│   ├── test_services/            # Business logic tests
│   ├── test_models/              # Model and repository tests
│   └── test_integration/         # Service integration tests
├── requirements.txt
├── Dockerfile
└── README.md
```

### Data Flow Pattern

#### Request Processing Flow:
```
1. HTTP Request → Controller Layer
   ├── Authentication & Authorization
   ├── Request validation
   └── Route to appropriate controller method

2. Controller → Service Layer
   ├── Business logic processing
   ├── Data validation and transformation
   └── Orchestrate multiple operations

3. Service → Model/Repository Layer
   ├── Data access operations
   ├── Database queries (Supabase)
   └── External service calls

4. Response Flow (reverse)
   ├── Repository → Service (data)
   ├── Service → Controller (processed data)
   └── Controller → HTTP Response (formatted)
```

### Design Pattern Benefits for Insurance Domain

#### Why This Pattern Works for Insurance Systems:

1. **Regulatory Compliance**: Clear separation allows easier audit trails
2. **Data Integrity**: Model layer ensures consistent data validation
3. **Business Logic Isolation**: Services layer contains complex insurance rules
4. **API Consistency**: Controllers ensure uniform API responses
5. **Testing**: Each layer can be tested independently for compliance
6. **Maintenance**: Insurance rules changes isolated in service layer

### Pattern Implementation Guidelines

#### Controller Layer Responsibilities:
- HTTP request/response handling
- Authentication and authorization
- Request validation and formatting
- Error handling and status codes
- API documentation and schemas

#### Service Layer Responsibilities:
- Business logic implementation
- Data transformation and validation
- External service integration
- Complex workflow orchestration
- Business rule enforcement

#### Model/Repository Layer Responsibilities:
- Data access patterns
- Database query optimization
- Data validation and constraints
- Supabase client management
- Cache management

## AI-Driven Data Processing Architecture (Level 3)

### Three-Level Design Pattern Extension

Building upon our Two-Level Architecture, we introduce **AI Agents** as a third level for intelligent data processing:

- **Level 1**: Microservices pattern (system architecture)
- **Level 2**: Model-Controller pattern (service architecture) 
- **Level 3**: AI Agents pattern (data processing intelligence)

### AI Agent Architecture

#### Core AI Agents

**1. Data Integrity Agent** 🔍
```
┌─────────────────────────────────────────────────────┐
│                DATA INTEGRITY AGENT                 │
├─────────────────────────────────────────────────────┤
│  Purpose: Intelligent data validation & consistency │
│  ┌─────────────────────────────────────────────────┐ │
│  │              AGENT CAPABILITIES                 │ │
│  │ • Business Rule Validation                      │ │
│  │ • Cross-Reference Data Checking                 │ │
│  │ • Referential Integrity Validation             │ │
│  │ • Insurance Domain Logic Validation            │ │
│  │ • Data Quality Assessment                      │ │
│  │ • Anomaly Detection                            │ │
│  └─────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────┤
│                     AGENT TOOLS                     │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────┐ │
│  │ Validation Tools│ │ Query Tools     │ │Log Tools│ │
│  │ • check_policy  │ │ • get_client    │ │• log_   │ │
│  │ • validate_date │ │ • get_policy    │ │  issues │ │
│  │ • verify_email  │ │ • check_exists  │ │• record │ │
│  │ • check_phone   │ │ • get_related   │ │  result │ │
│  └─────────────────┘ └─────────────────┘ └─────────┘ │
└─────────────────────────────────────────────────────┘
```

**2. DB Processing Agent** 🤖
```
┌─────────────────────────────────────────────────────┐
│                DB PROCESSING AGENT                  │
├─────────────────────────────────────────────────────┤
│  Purpose: Intelligent database operations & optimization │
│  ┌─────────────────────────────────────────────────┐ │
│  │              AGENT CAPABILITIES                 │ │
│  │ • Query Strategy Optimization                   │ │
│  │ • Transaction Management                        │ │
│  │ • Error Recovery & Retry Logic                 │ │
│  │ • Performance Optimization                     │ │
│  │ • Batch Operation Intelligence                 │ │
│  │ • Relationship Management                      │ │
│  └─────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────┤
│                     AGENT TOOLS                     │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────┐ │
│  │ CRUD Tools      │ │ Query Tools     │ │Txn Tools│ │
│  │ • create_record │ │ • find_by_id    │ │• begin  │ │
│  │ • update_record │ │ • search_data   │ │• commit │ │
│  │ • delete_record │ │ • join_tables   │ │• rollbck│ │
│  │ • bulk_insert   │ │ • aggregate     │ │• savepit│ │
│  └─────────────────┘ └─────────────────┘ └─────────┘ │
└─────────────────────────────────────────────────────┘
```

### Agent Integration Flow

#### Data Processing Pipeline with AI Agents
```
1. 📥 Data Input → Service Layer
   ├── Business logic validation
   ├── Initial data preparation
   └── Route to Data Integrity Agent

2. 🔍 Data Integrity Agent Processing
   ├── Analyze data structure and content
   ├── Validate business rules using tools:
   │   ├── check_policy_validity()
   │   ├── validate_client_data()
   │   ├── verify_relationships()
   │   └── assess_data_quality()
   ├── Cross-reference with existing data
   ├── Generate integrity report
   └── Pass validated data to DB Processing Agent

3. 🤖 DB Processing Agent Operations
   ├── Receive validated data from Integrity Agent
   ├── Analyze optimal database strategy:
   │   ├── Choose appropriate CRUD operations
   │   ├── Determine transaction boundaries
   │   ├── Select optimal query patterns
   │   └── Plan error recovery strategy
   ├── Execute database operations using tools:
   │   ├── create_record() / update_record()
   │   ├── find_by_id() / search_data()
   │   ├── begin_transaction() / commit()
   │   └── handle_errors() / retry_operation()
   ├── Monitor operation performance
   └── Return results to Service Layer

4. 📤 Result Processing → Service Layer
   ├── Process agent results
   ├── Handle any errors or exceptions
   ├── Update application state
   └── Return response to Controller
```

### AI Agent Implementation

#### Agent Base Class
```python
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod
import httpx
from pydantic import BaseModel

class AgentTool(BaseModel):
    """Base class for agent tools"""
    name: str
    description: str
    parameters: Dict[str, Any]

class AIAgent(ABC):
    """Base class for AI agents"""
    
    def __init__(self, name: str, model: str = "mistral-large-latest"):
        self.name = name
        self.model = model
        self.client = httpx.AsyncClient()
        self.tools = self._setup_tools()
        self.system_prompt = self._get_system_prompt()
    
    @abstractmethod
    def _setup_tools(self) -> List[AgentTool]:
        """Setup agent-specific tools"""
        pass
    
    @abstractmethod
    def _get_system_prompt(self) -> str:
        """Get agent system prompt"""
        pass
    
    async def process(self, data: Dict[str, Any], context: Optional[Dict] = None) -> Dict[str, Any]:
        """Process data using AI with available tools"""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"Process this data: {data}"}
        ]
        
        if context:
            messages.append({"role": "user", "content": f"Additional context: {context}"})
        
        # Use Mistral API or Grok API for AI processing
        response = await self._call_ai_api(messages, self.tools)
        
        return await self._handle_response(response, data)
    
    async def _handle_response(self, response, original_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle AI response and execute tool calls"""
        result = {
            "success": True,
            "data": original_data,
            "agent_actions": [],
            "validation_results": [],
            "errors": []
        }
        
        if response.choices[0].message.tool_calls:
            for tool_call in response.choices[0].message.tool_calls:
                try:
                    tool_result = await self._execute_tool(
                        tool_call.function.name,
                        tool_call.function.arguments
                    )
                    result["agent_actions"].append({
                        "tool": tool_call.function.name,
                        "result": tool_result
                    })
                except Exception as e:
                    result["errors"].append({
                        "tool": tool_call.function.name,
                        "error": str(e)
                    })
                    result["success"] = False
        
        return result
    
    @abstractmethod
    async def _execute_tool(self, tool_name: str, arguments: str) -> Any:
        """Execute a specific tool"""
        pass
```

#### Service Integration with AI Agents
```python
# Enhanced service layer with AI agents
from typing import Dict, Any, Optional
from .ai_agents import DataIntegrityAgent, DBProcessingAgent

class EnhancedClientService:
    """Client service with AI-powered data processing"""
    
    def __init__(
        self,
        supabase_client,
        data_integrity_agent: DataIntegrityAgent,
        db_processing_agent: DBProcessingAgent
    ):
        self.supabase = supabase_client
        self.integrity_agent = data_integrity_agent
        self.db_agent = db_processing_agent
    
    async def create_client(self, client_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create client with AI-powered validation and processing"""
        
        # Step 1: Data integrity validation
        integrity_result = await self.integrity_agent.process(
            data=client_data,
            context={"operation": "create_client", "table": "clients"}
        )
        
        if not integrity_result["success"]:
            return {
                "success": False,
                "errors": integrity_result["errors"],
                "validation_issues": integrity_result.get("validation_results", [])
            }
        
        # Step 2: DB processing with validated data
        db_result = await self.db_agent.process(
            data={
                "operation": "create",
                "table": "clients",
                "record_data": client_data
            },
            context={
                "integrity_check": integrity_result,
                "business_context": "client_creation"
            }
        )
        
        return {
            "success": db_result["success"],
            "client": db_result.get("data"),
            "integrity_report": integrity_result,
            "processing_report": db_result,
            "errors": db_result.get("errors", [])
        }
```

### Benefits of AI-Driven Data Processing

#### 🧠 **Intelligence Benefits:**
- **Adaptive Logic**: Agents can adapt to different data scenarios
- **Context Awareness**: Understanding business context for better decisions
- **Error Prevention**: Advanced validation before data corruption
- **Optimization**: Intelligent query and operation optimization
- **Learning**: Agents can improve over time with feedback

#### 🔒 **Data Integrity Benefits:**
- **Multi-layer Validation**: AI + business rules + database constraints
- **Relationship Verification**: Intelligent referential integrity checking
- **Quality Assessment**: Automated data quality scoring
- **Anomaly Detection**: Unusual patterns and potential issues
- **Compliance Checking**: Insurance regulation compliance validation

#### 🚀 **Performance Benefits:**
- **Query Optimization**: AI chooses optimal database strategies
- **Batch Intelligence**: Smart batching for better performance
- **Error Recovery**: Intelligent retry and recovery mechanisms
- **Resource Management**: Optimal resource utilization
- **Caching Strategies**: AI-driven caching decisions

#### 📊 **Business Benefits:**
- **Audit Trails**: Detailed logs of all AI decisions and actions
- **Regulatory Compliance**: Enhanced compliance with insurance regulations
- **Risk Mitigation**: Proactive risk identification and prevention
- **Decision Transparency**: Clear reasoning for all data operations
- **Continuous Improvement**: Agents learn from past operations

### Implementation Strategy

#### Phase 1: Basic AI Agents (Weeks 1-2)
- [ ] Implement base AIAgent class
- [ ] Create Data Integrity Agent with core validation tools
- [ ] Create DB Processing Agent with basic CRUD tools
- [ ] Integrate agents into one service (pilot)

#### Phase 2: Advanced Intelligence (Weeks 3-4)
- [ ] Add advanced validation rules for insurance domain
- [ ] Implement query optimization in DB agent
- [ ] Add error recovery and retry mechanisms
- [ ] Enhance logging and monitoring

#### Phase 3: Full Integration (Weeks 5-6)
- [ ] Integrate agents into all microservices
- [ ] Add performance monitoring and metrics
- [ ] Implement agent learning and feedback loops
- [ ] Complete testing and documentation

### Agent Configuration

#### Environment Configuration
```env
# AI Agent Configuration
ENABLE_AI_AGENTS=true
AI_AGENT_MODEL=mistral-large-latest  # or grok-beta for Grok
AI_AGENT_PROVIDER=mistral  # mistral or grok
AI_AGENT_TEMPERATURE=0.1
MISTRAL_API_KEY=your-mistral-api-key
# GROK_API_KEY=your-grok-api-key  # Alternative for Grok

# Agent Behavior
DATA_INTEGRITY_STRICTNESS=high  # low, medium, high
DB_PROCESSING_OPTIMIZATION=enabled
AGENT_LOGGING_LEVEL=detailed
AGENT_RETRY_ATTEMPTS=3

# Performance Settings
AGENT_TIMEOUT_SECONDS=30
AGENT_CONCURRENT_REQUESTS=5
ENABLE_AGENT_CACHING=true
```

This **Three-Level AI-Enhanced Architecture** combines:
1. **Microservices** (system scalability)
2. **Model-Controller** (code maintainability) 
3. **AI Agents** (intelligent data processing)

Creating an enterprise-grade, intelligent insurance management system perfect for Hong Kong's market requirements.

## Document Storage Architecture

### Hybrid Storage Strategy: **Supabase Storage + AWS S3**

The system implements a sophisticated document storage architecture optimized for performance, cost-effectiveness, and regulatory compliance:

#### **Primary Storage: Supabase Storage**
- **Use Case**: Active documents, recent uploads, frequently accessed files
- **Features**: 
  - Built-in Row-Level Security (RLS) integration
  - Automatic CDN distribution
  - Real-time image transformations
  - Seamless authentication integration
- **Pricing**: $0.021/GB storage, $0.09/GB bandwidth
- **Retention**: 90 days for active documents

#### **Archive Storage: AWS S3 Intelligent Tiering**
- **Use Case**: Long-term storage, compliance archives, backup
- **Features**:
  - 99.999999999% (11 9's) durability
  - Automatic lifecycle management
  - Cross-region replication
  - Intelligent tiering (Standard → IA → Glacier → Deep Archive)
- **Pricing**: $0.0125/GB (Glacier), $0.00099/GB (Deep Archive)
- **Retention**: 7+ years for compliance

```mermaid
flowchart TD
    A[Document Upload] --> B{File Analysis}
    B --> C[Virus Scan]
    C --> D[AI Document Classification]
    D --> E[Supabase Storage]
    E --> F[Processing Pipeline]
    F --> G[OCR/AI Processing]
    G --> H[Metadata Extraction]
    H --> I[Database Record]
    
    %% Lifecycle Management
    E --> J[90-Day Lifecycle]
    J --> K[AWS S3 Standard]
    K --> L[S3 Intelligent Tiering]
    L --> M[Glacier/Deep Archive]
    
    %% Security Layer
    C --> N[Encryption at Rest]
    N --> O[Access Control]
    O --> P[Audit Logging]
```

### Document Processing Pipeline

#### **1. Upload & Validation**
```python
from supabase import Client
from typing import Dict, Any, List
import hashlib
import magic
from datetime import datetime, timedelta

class DocumentStorageService:
    """Hybrid document storage with Supabase + AWS S3"""
    
    def __init__(self, supabase_client: Client, s3_client, ai_agent):
        self.supabase = supabase_client
        self.s3 = s3_client
        self.ai_agent = ai_agent
        
        # Allowed file types for insurance documents
        self.allowed_types = {
            'application/pdf': 'pdf',
            'image/jpeg': 'jpg',
            'image/png': 'png',
            'image/tiff': 'tiff',
            'application/msword': 'doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
            'application/vnd.ms-excel': 'xls',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx'
        }
        
        # File size limits (MB)
        self.size_limits = {
            'pdf': 50,
            'image': 20,
            'document': 25
        }
    
    async def upload_document(
        self,
        file_content: bytes,
        filename: str,
        client_id: str,
        document_type: str,
        metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Upload document with comprehensive validation and processing"""
        
        try:
            # Step 1: File validation
            validation_result = await self._validate_file(file_content, filename)
            if not validation_result['valid']:
                return {'success': False, 'errors': validation_result['errors']}
            
            # Step 2: Generate unique file path
            file_hash = hashlib.sha256(file_content).hexdigest()
            file_ext = validation_result['extension']
            storage_path = f"documents/{client_id}/{datetime.now().year}/{file_hash}.{file_ext}"
            
            # Step 3: Upload to Supabase Storage
            upload_result = await self._upload_to_supabase(
                file_content, storage_path, validation_result['mime_type']
            )
            
            # Step 4: AI-powered document classification
            ai_classification = await self.ai_agent.classify_document(
                file_content, filename, document_type
            )
            
            # Step 5: Create database record
            document_record = {
                'id': str(uuid.uuid4()),
                'client_id': client_id,
                'original_filename': filename,
                'storage_path': storage_path,
                'file_hash': file_hash,
                'file_size': len(file_content),
                'mime_type': validation_result['mime_type'],
                'document_type': document_type,
                'ai_classification': ai_classification,
                'storage_provider': 'supabase',
                'metadata': metadata or {},
                'created_at': datetime.now().isoformat(),
                'archive_date': (datetime.now() + timedelta(days=90)).isoformat()
            }
            
            # Step 6: Save to database
            db_result = await self.supabase.table('documents').insert(document_record).execute()
            
            # Step 7: Schedule OCR processing if applicable
            if validation_result['mime_type'] in ['application/pdf', 'image/jpeg', 'image/png']:
                await self._schedule_ocr_processing(document_record['id'])
            
            return {
                'success': True,
                'document': {
                    'id': document_record['id'],
                    'storage_path': storage_path,
                    'download_url': upload_result['public_url'],
                    'ai_classification': ai_classification,
                    'processing_status': 'uploaded'
                }
            }
            
        except Exception as e:
            return {'success': False, 'errors': [str(e)]}
    
    async def _validate_file(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """Comprehensive file validation"""
        errors = []
        
        # Check file size
        file_size_mb = len(file_content) / (1024 * 1024)
        if file_size_mb > 50:  # 50MB limit
            errors.append(f"File size ({file_size_mb:.1f}MB) exceeds 50MB limit")
        
        # Check file type
        mime_type = magic.from_buffer(file_content, mime=True)
        if mime_type not in self.allowed_types:
            errors.append(f"File type {mime_type} not allowed")
        
        # Check file extension
        file_ext = filename.split('.')[-1].lower()
        expected_ext = self.allowed_types.get(mime_type)
        if file_ext != expected_ext:
            errors.append(f"File extension {file_ext} doesn't match content type {mime_type}")
        
        # Virus scan (placeholder - integrate with actual scanner)
        if await self._virus_scan(file_content):
            errors.append("File failed virus scan")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'mime_type': mime_type,
            'extension': expected_ext,
            'size_mb': file_size_mb
        }
    
    async def _upload_to_supabase(
        self, 
        file_content: bytes, 
        storage_path: str, 
        mime_type: str
    ) -> Dict[str, Any]:
        """Upload to Supabase Storage with encryption"""
        
        # Upload with metadata
        upload_result = await self.supabase.storage.from_('documents').upload(
            path=storage_path,
            file=file_content,
            file_options={
                'content-type': mime_type,
                'cache-control': '3600',
                'upsert': False
            }
        )
        
        # Get public URL
        public_url = self.supabase.storage.from_('documents').get_public_url(storage_path)
        
        return {
            'success': True,
            'storage_path': storage_path,
            'public_url': public_url,
            'provider': 'supabase'
        }
```

#### **2. Lifecycle Management**
```python
class DocumentLifecycleManager:
    """Manages document lifecycle from upload to archive"""
    
    async def archive_old_documents(self):
        """Move documents older than 90 days to AWS S3"""
        
        # Get documents ready for archiving
        archive_candidates = await self.supabase.table('documents').select('*').lt(
            'archive_date', datetime.now().isoformat()
        ).eq('storage_provider', 'supabase').execute()
        
        for document in archive_candidates.data:
            try:
                # Download from Supabase
                file_content = await self.supabase.storage.from_('documents').download(
                    document['storage_path']
                )
                
                # Upload to S3 with intelligent tiering
                s3_key = f"archive/{document['storage_path']}"
                await self.s3.put_object(
                    Bucket='insurance-documents-archive',
                    Key=s3_key,
                    Body=file_content,
                    StorageClass='INTELLIGENT_TIERING',
                    ServerSideEncryption='AES256',
                    Metadata={
                        'client_id': document['client_id'],
                        'original_filename': document['original_filename'],
                        'archived_date': datetime.now().isoformat()
                    }
                )
                
                # Update database record
                await self.supabase.table('documents').update({
                    'storage_provider': 'aws_s3',
                    'storage_path': s3_key,
                    'archived_at': datetime.now().isoformat()
                }).eq('id', document['id']).execute()
                
                # Delete from Supabase Storage
                await self.supabase.storage.from_('documents').remove([document['storage_path']])
                
            except Exception as e:
                # Log error but continue with other documents
                logger.error(f"Failed to archive document {document['id']}: {str(e)}")
```

#### **3. Security & Access Control**

```python
# Row-Level Security Policy for Supabase
"""
-- RLS Policy for documents table
CREATE POLICY "Users can only access their own documents"
ON documents
FOR ALL
USING (
  auth.uid()::text = client_id OR
  auth.jwt() ->> 'role' = 'admin' OR
  (auth.jwt() ->> 'role' = 'broker' AND client_id = ANY(
    SELECT client_id FROM broker_clients WHERE broker_id = auth.uid()::text
  ))
);

-- Storage RLS Policy
CREATE POLICY "Authenticated users can view documents"
ON storage.objects
FOR SELECT
USING (auth.role() = 'authenticated');

CREATE POLICY "Users can upload documents"
ON storage.objects
FOR INSERT
WITH CHECK (auth.role() = 'authenticated');
"""

class DocumentAccessControl:
    """Handles document access control and permissions"""
    
    async def get_document_with_access_check(
        self, 
        document_id: str, 
        user_id: str, 
        user_role: str
    ) -> Dict[str, Any]:
        """Get document with access control"""
        
        # Check access permission
        if not await self._check_document_access(document_id, user_id, user_role):
            return {'success': False, 'error': 'Access denied'}
        
        # Get document metadata
        document = await self.supabase.table('documents').select('*').eq(
            'id', document_id
        ).single().execute()
        
        if not document.data:
            return {'success': False, 'error': 'Document not found'}
        
        # Generate signed URL based on storage provider
        if document.data['storage_provider'] == 'supabase':
            signed_url = await self.supabase.storage.from_('documents').create_signed_url(
                document.data['storage_path'], 3600  # 1 hour expiry
            )
        else:
            # Generate S3 signed URL
            signed_url = await self.s3.generate_presigned_url(
                'get_object',
                Params={'Bucket': 'insurance-documents-archive', 'Key': document.data['storage_path']},
                ExpiresIn=3600
            )
        
        return {
            'success': True,
            'document': document.data,
            'download_url': signed_url,
            'expires_at': (datetime.now() + timedelta(hours=1)).isoformat()
        }
```

### Cost Optimization Strategy

#### **Storage Costs Analysis**
```python
# Cost calculator for document storage
class StorageCostCalculator:
    """Calculate and optimize storage costs"""
    
    def __init__(self):
        self.supabase_costs = {
            'storage_per_gb': 0.021,
            'bandwidth_per_gb': 0.09
        }
        
        self.s3_costs = {
            'standard': 0.023,
            'ia': 0.0125,
            'glacier': 0.004,
            'deep_archive': 0.00099
        }
    
    def calculate_monthly_costs(self, usage_stats: Dict) -> Dict[str, float]:
        """Calculate monthly storage costs"""
        
        # Supabase costs (active documents)
        supabase_storage_cost = usage_stats['active_documents_gb'] * self.supabase_costs['storage_per_gb']
        supabase_bandwidth_cost = usage_stats['monthly_downloads_gb'] * self.supabase_costs['bandwidth_per_gb']
        
        # S3 costs (archived documents)
        s3_cost = 0
        for tier, gb_amount in usage_stats['s3_storage'].items():
            s3_cost += gb_amount * self.s3_costs[tier]
        
        total_cost = supabase_storage_cost + supabase_bandwidth_cost + s3_cost
        
        return {
            'supabase_storage': supabase_storage_cost,
            'supabase_bandwidth': supabase_bandwidth_cost,
            's3_archive': s3_cost,
            'total_monthly': total_cost,
            'cost_per_document': total_cost / usage_stats['total_documents']
        }
```

#### **Performance Optimization**

```python
class DocumentPerformanceOptimizer:
    """Optimize document storage and retrieval performance"""
    
    async def optimize_document_access(self, client_id: str) -> Dict[str, Any]:
        """Optimize document access patterns for specific client"""
        
        # Analyze access patterns
        access_stats = await self._analyze_access_patterns(client_id)
        
        # Pre-generate signed URLs for frequently accessed documents
        if access_stats['frequent_access_documents']:
            await self._pregenerate_signed_urls(access_stats['frequent_access_documents'])
        
        # Suggest moving hot documents back to Supabase
        hot_documents = access_stats['hot_archived_documents']
        if hot_documents:
            await self._suggest_document_migration(hot_documents, 'supabase')
        
        return {
            'optimizations_applied': access_stats['optimizations'],
            'performance_improvement': access_stats['estimated_improvement'],
            'cost_impact': access_stats['cost_impact']
        }
```

### Monitoring & Analytics

#### **Document Storage Metrics**
- **Storage utilization**: Supabase vs S3 distribution
- **Access patterns**: Frequency, timing, user behavior
- **Cost tracking**: Monthly storage and bandwidth costs
- **Performance metrics**: Upload/download speeds, availability
- **Security events**: Access attempts, permission changes

#### **Dashboard Integration**
```python
# Document storage dashboard metrics
async def get_storage_dashboard_metrics():
    """Get comprehensive storage metrics for dashboard"""
    
    return {
        'total_documents': await get_total_document_count(),
        'active_storage_gb': await get_supabase_storage_usage(),
        'archived_storage_gb': await get_s3_storage_usage(),
        'monthly_cost': await calculate_current_month_cost(),
        'access_patterns': await get_access_pattern_summary(),
        'security_events': await get_recent_security_events(),
        'performance_metrics': {
            'avg_upload_time': await get_avg_upload_time(),
            'avg_download_time': await get_avg_download_time(),
            'availability': await get_storage_availability()
        }
    }
```

This hybrid storage architecture provides:
- **99.9% availability** for active documents
- **Cost optimization** through intelligent tiering
- **Regulatory compliance** with 7+ year retention
- **Performance optimization** with CDN distribution
- **Security** with RLS and encryption
- **Scalability** to handle growth from SME to enterprise

### Technology Stack

#### Backend Core
- **Framework**: FastAPI (recommended) or Flask
- **Database**: PostgreSQL (existing schema)
- **ORM**: SQLAlchemy with Alembic for migrations
- **Authentication**: JWT with role-based access control
- **API Documentation**: OpenAPI/Swagger (built-in with FastAPI)

#### Infrastructure & DevOps
- **Task Queue**: Celery with Redis/RabbitMQ
- **Caching**: Redis for session management and caching
- **File Storage**: Hybrid approach with Supabase Storage (primary) + AWS S3 (archive)
- **Logging**: Structured logging with ELK stack or similar
- **Monitoring**: Prometheus + Grafana or similar

#### AI & External Services
- **AI Agents**: Grok or Mistral AI for intelligent data processing
- **OCR**: Mistral AI (existing) + fallback to Tesseract
- **LLM**: Mistral AI for content generation and intelligent processing
- **Agent Tools**: Custom Supabase integration tools for database operations
- **Email Service**: SendGrid/AWS SES for transactional emails
- **Notification**: Twilio for SMS, Push notifications

## API Design Standards

### RESTful Design Principles

#### URL Structure
```
/api/v1/{resource}/{id?}/{sub-resource?}

Examples:
GET    /api/v1/clients                    # List clients
GET    /api/v1/clients/{id}               # Get specific client
POST   /api/v1/clients                    # Create client
PUT    /api/v1/clients/{id}               # Update client
DELETE /api/v1/clients/{id}               # Delete client
GET    /api/v1/clients/{id}/policies      # Get client's policies
POST   /api/v1/policies/{id}/renew        # Renew specific policy
```

#### HTTP Status Codes
- `200 OK` - Successful GET, PUT, PATCH
- `201 Created` - Successful POST
- `204 No Content` - Successful DELETE
- `400 Bad Request` - Client error (validation failed)
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Access denied
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource conflict
- `422 Unprocessable Entity` - Validation error
- `500 Internal Server Error` - Server error

#### Request/Response Format
```json
{
  "success": true,
  "data": {
    // Response data
  },
  "meta": {
    "timestamp": "2024-01-01T00:00:00Z",
    "request_id": "uuid-here",
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total": 100,
      "pages": 5
    }
  },
  "errors": []
}
```

### Core API Endpoints

#### Authentication & Authorization
```
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
POST   /api/v1/auth/refresh
GET    /api/v1/auth/profile
PUT    /api/v1/auth/profile
```

#### Client Management
```
GET    /api/v1/clients
POST   /api/v1/clients
GET    /api/v1/clients/{id}
PUT    /api/v1/clients/{id}
DELETE /api/v1/clients/{id}
GET    /api/v1/clients/{id}/policies
GET    /api/v1/clients/{id}/documents
```

#### Policy Management
```
GET    /api/v1/policies
POST   /api/v1/policies
GET    /api/v1/policies/{id}
PUT    /api/v1/policies/{id}
DELETE /api/v1/policies/{id}
POST   /api/v1/policies/{id}/renew
POST   /api/v1/policies/{id}/amend
GET    /api/v1/policies/renewals/upcoming
```

#### Document Management & OCR
```
POST   /api/v1/documents/upload
GET    /api/v1/documents/{id}
DELETE /api/v1/documents/{id}
POST   /api/v1/documents/{id}/ocr
GET    /api/v1/documents/{id}/ocr-results
```

#### Quotation Management
```
GET    /api/v1/quotations
POST   /api/v1/quotations
GET    /api/v1/quotations/{id}
PUT    /api/v1/quotations/{id}
POST   /api/v1/quotations/{id}/submit
GET    /api/v1/quotations/{id}/status
```

#### Communication & Notifications
```
POST   /api/v1/communications/email
GET    /api/v1/communications/templates
POST   /api/v1/notifications/renewal-reminders
GET    /api/v1/notifications/settings
```

## Security Design

### Authentication & Authorization

#### JWT Implementation
```python
# Token structure
{
  "user_id": "uuid",
  "email": "user@example.com",
  "role": "broker|admin|client",
  "permissions": ["read:policies", "write:policies"],
  "exp": 1234567890,
  "iat": 1234567890
}
```

#### Role-Based Access Control (RBAC)
- **Admin**: Full system access
- **Broker**: Client and policy management
- **Client**: Own data access only
- **Underwriter**: Quotation and policy review

#### Permission Matrix
```
Resource      | Admin | Broker | Client | Underwriter
--------------|-------|--------|--------|-----------
Clients       | CRUD  | CRUD   | R(own) | R
Policies      | CRUD  | CRUD   | R(own) | RU
Quotations    | CRUD  | CRUD   | R(own) | RU
Documents     | CRUD  | CRUD   | R(own) | R
Reports       | CRUD  | R      | R(own) | R
```

### Data Protection

#### Encryption Standards
- **At Rest**: AES-256 for sensitive data (PII, financial)
- **In Transit**: TLS 1.3 for all API communications
- **Database**: Encrypted fields for sensitive columns
- **File Storage**: Encrypted document storage

#### Secret Management
Utilize existing `secrets` table with enhancements:
```sql
-- Enhanced secrets table
ALTER TABLE secrets ADD COLUMN key_version INTEGER DEFAULT 1;
ALTER TABLE secrets ADD COLUMN rotation_date TIMESTAMP;
ALTER TABLE secrets ADD COLUMN access_level VARCHAR(50) DEFAULT 'system';
```

#### Environment Configuration
```env
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/insurance_db
DATABASE_POOL_SIZE=20

# JWT
JWT_SECRET_KEY=your-secret-key-here
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# AI Services
MISTRAL_API_KEY=your-mistral-key
GROK_API_KEY=your-grok-key

# External Services
SENDGRID_API_KEY=your-sendgrid-key
TWILIO_ACCOUNT_SID=your-twilio-sid
TWILIO_AUTH_TOKEN=your-twilio-token

# Storage
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
S3_BUCKET_NAME=insurance-documents

# Redis
REDIS_URL=redis://localhost:6379/0

# Security
ALLOWED_HOSTS=["localhost", "yourdomain.com"]
CORS_ORIGINS=["http://localhost:3000", "https://yourdomain.com"]
```

## Database Design

### Enhanced Schema Recommendations

#### New Tables for API Management
```sql
-- API Keys and Access Control
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    user_id UUID REFERENCES users(id),
    permissions JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Audit Logs
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Renewal Schedules
CREATE TABLE renewal_schedules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID NOT NULL,
    renewal_date DATE NOT NULL,
    reminder_dates DATE[] NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    auto_renew BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Policy Amendments
CREATE TABLE policy_amendments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID NOT NULL,
    amendment_type VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    effective_date DATE NOT NULL,
    premium_change DECIMAL(10,2) DEFAULT 0,
    status VARCHAR(50) DEFAULT 'draft',
    created_by UUID NOT NULL,
    approved_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);
```

### Data Relationships and Indexes
```sql
-- Performance Indexes
CREATE INDEX idx_clients_email ON clients(email);
CREATE INDEX idx_documents_client_id ON documents(client_id);
CREATE INDEX idx_quotations_status ON quotations(status);
CREATE INDEX idx_renewal_schedules_date ON renewal_schedules(renewal_date);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);

-- Full-text search indexes
CREATE INDEX idx_clients_search ON clients USING GIN(to_tsvector('english', company_name || ' ' || contact_name));
CREATE INDEX idx_documents_search ON documents USING GIN(to_tsvector('english', original_file_name));
```

## Implementation Guidelines

### Project Structure
```
broker-tool-desktop-api/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application entry point
│   ├── config.py               # Configuration management
│   ├── database.py             # Database connection and session
│   ├── dependencies.py         # Dependency injection
│   ├── exceptions.py           # Custom exception handlers
│   ├── middleware.py           # Custom middleware
│   ├── models/                 # SQLAlchemy models
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── client.py
│   │   ├── policy.py
│   │   ├── document.py
│   │   └── user.py
│   ├── schemas/                # Pydantic schemas
│   │   ├── __init__.py
│   │   ├── client.py
│   │   ├── policy.py
│   │   ├── document.py
│   │   └── user.py
│   ├── api/                    # API routes
│   │   ├── __init__.py
│   │   ├── v1/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py
│   │   │   ├── clients.py
│   │   │   ├── policies.py
│   │   │   ├── documents.py
│   │   │   └── quotations.py
│   ├── core/                   # Core business logic
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── security.py
│   │   └── permissions.py
│   ├── services/               # Business services
│   │   ├── __init__.py
│   │   ├── client_service.py
│   │   ├── policy_service.py
│   │   ├── document_service.py
│   │   ├── ocr_service.py
│   │   ├── email_service.py
│   │   └── notification_service.py
│   ├── utils/                  # Utility functions
│   │   ├── __init__.py
│   │   ├── helpers.py
│   │   ├── validators.py
│   │   └── formatters.py
│   └── tasks/                  # Background tasks
│       ├── __init__.py
│       ├── renewal_reminders.py
│       ├── document_processing.py
│       └── email_tasks.py
├── alembic/                    # Database migrations
├── tests/                      # Test files
├── scripts/                    # Utility scripts
├── requirements.txt            # Python dependencies
├── .env                        # Environment variables
├── .env.example               # Environment template
├── docker-compose.yml         # Docker configuration
├── Dockerfile                 # Docker build file
└── README.md                  # Project documentation
```

### Development Workflow

#### 1. Setup Development Environment
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup database
alembic upgrade head

# Run development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### 2. Database Migration Management
```bash
# Create new migration
alembic revision --autogenerate -m "Add new table"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

#### 3. Testing Strategy
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_client_service.py
```

### Key Implementation Considerations

1. **Gradual Migration**: Migrate from n8n workflows to REST API endpoints incrementally
2. **Backward Compatibility**: Maintain webhook endpoints during transition period
3. **Error Handling**: Implement comprehensive error handling and logging
4. **Performance**: Use database connection pooling and query optimization
5. **Monitoring**: Implement health checks and metrics collection
6. **Documentation**: Auto-generate API documentation with examples

### Next Steps

1. **Phase 1**: Setup project structure and basic CRUD operations
2. **Phase 2**: Implement authentication and authorization
3. **Phase 3**: Migrate OCR and AI services to REST endpoints
4. **Phase 4**: Implement renewal reminder system
5. **Phase 5**: Add advanced features and optimizations

---

*This design document serves as the foundation for implementing a robust, scalable insurance renewal management system. Each section should be expanded based on specific implementation needs and business requirements.* 