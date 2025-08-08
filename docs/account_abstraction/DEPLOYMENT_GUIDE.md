# BlockAuth Hybrid Web2/Web3 Account Abstraction Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the BlockAuth **Hybrid Account Abstraction** system to different environments while ensuring **zero downtime** for existing Web2 authentication users.

## CRITICAL DEPLOYMENT PRINCIPLE

**Account Abstraction deployment MUST be implemented as a zero-downtime migration that preserves all existing Web2 authentication functionality. Web2 users must experience no service interruption during the deployment process.**

### Deployment Safety Requirements
- **Zero Breaking Changes**: All existing Web2 APIs must continue working during and after deployment
- **Gradual Rollout**: Web3 features are deployed with feature flags initially disabled
- **Rollback Ready**: Complete rollback plan to disable Web3 features if issues arise
- **Data Preservation**: All existing user data, preferences, and authentication history must be preserved
- **Performance Monitoring**: Continuous monitoring to ensure Web2 performance is not degraded

## Prerequisites

### System Requirements

- **Node.js**: >= 18.0.0
- **Python**: >= 3.9
- **PostgreSQL**: >= 13.0
- **Redis**: >= 6.0
- **Docker**: >= 20.0 (for containerized deployment)
- **Git**: Latest version

### Development Tools

```bash
# Install global dependencies
npm install -g hardhat yarn
pip install poetry

# Ethereum development tools
npm install -g @account-abstraction/bundler
npm install -g @account-abstraction/utils
```

### External Services

1. **Ethereum Node Providers**
   - Infura, Alchemy, or QuickNode account
   - API keys for testnet and mainnet

2. **Bundler Services**
   - Stackup API key
   - Biconomy API key
   - Or self-hosted bundler

3. **Monitoring & Analytics**
   - DataDog or New Relic account
   - Sentry for error tracking
   - Mixpanel or Amplitude for analytics

## Pre-Deployment Checklist (MANDATORY)

### Web2 Compatibility Verification
- [ ] **All existing Web2 tests pass** without modification
- [ ] **Performance benchmarks** show no degradation in Web2 authentication
- [ ] **Database migrations** are additive only (no breaking schema changes)
- [ ] **API backward compatibility** verified with existing client applications
- [ ] **Authentication flows** preserve existing JWT, OAuth, and OTP functionality

### Rollback Preparedness
- [ ] **Feature flags** configured to disable Web3 features instantly
- [ ] **Database rollback** scripts prepared and tested
- [ ] **Configuration rollback** procedures documented
- [ ] **Monitoring alerts** configured for immediate issue detection
- [ ] **Emergency contacts** and escalation procedures established

### Security Validation
- [ ] **Smart contracts** audited and verified on testnet
- [ ] **Migration endpoints** security tested
- [ ] **Hybrid authentication** penetration tested
- [ ] **Data encryption** verified for Web3 user data
- [ ] **Access controls** validated for AA administrative functions

## Environment Setup

### Development Environment (WEB2 PRESERVATION FIRST)

#### 1. Clone Repository and Verify Web2 Functionality
```bash
git clone https://github.com/BloclabsHQ/BlocAuth/auth-pack.git
cd auth-pack
```

#### 2. Install Dependencies
```bash
# Python dependencies
poetry install
poetry shell

# Node.js dependencies
npm install

# Install Hardhat plugins
npm install --save-dev @nomicfoundation/hardhat-toolbox
npm install --save-dev @openzeppelin/hardhat-upgrades
```

#### 3. Environment Configuration
```bash
# Copy environment template
cp .env.example .env.development

# Edit configuration
nano .env.development
```

**Environment Variables:**
```bash
# Database
DATABASE_URL=postgresql://blockauth:password@localhost:5432/blockauth_dev
REDIS_URL=redis://localhost:6379/0

# Blockchain
ETHEREUM_NETWORK=sepolia
INFURA_API_KEY=your_infura_key
PRIVATE_KEY=your_deployment_private_key
ETHERSCAN_API_KEY=your_etherscan_key

# Account Abstraction
AA_ENTRY_POINT_ADDRESS=0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
BUNDLER_API_KEY=your_bundler_key
BUNDLER_URL=https://api.stackup.sh/v1/node/your_api_key

# Security
SECRET_KEY=your-super-secret-django-key
JWT_SECRET=your-jwt-secret

# Monitoring
SENTRY_DSN=https://your-sentry-dsn
DATADOG_API_KEY=your_datadog_key

# Feature Flags
ACCOUNT_ABSTRACTION_ENABLED=true
PAYMASTER_ENABLED=true
BATCH_OPERATIONS_ENABLED=true
```

#### 4. Database Setup
```bash
# Start PostgreSQL and Redis
sudo service postgresql start
sudo service redis-server start

# Create database
createdb blockauth_dev

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser
```

#### 5. Smart Contract Development Setup
```bash
# Compile contracts
npx hardhat compile

# Run tests
npx hardhat test

# Deploy to local network
npx hardhat node --fork https://sepolia.infura.io/v3/YOUR_INFURA_KEY
npx hardhat run scripts/deploy.js --network localhost
```

### Staging Environment

#### 1. Infrastructure Setup

**Docker Compose Configuration:**
```yaml
# docker-compose.staging.yml
version: '3.8'

services:
  web:
    build: 
      context: .
      dockerfile: Dockerfile.staging
    ports:
      - "8000:8000"
    environment:
      - DJANGO_SETTINGS_MODULE=blockauth.settings.staging
      - DATABASE_URL=postgresql://blockauth:${DB_PASSWORD}@db:5432/blockauth_staging
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs

  db:
    image: postgres:13
    environment:
      POSTGRES_DB: blockauth_staging
      POSTGRES_USER: blockauth
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6-alpine
    volumes:
      - redis_data:/data

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - web

  celery:
    build: 
      context: .
      dockerfile: Dockerfile.staging
    command: celery -A blockauth worker -l info
    environment:
      - DJANGO_SETTINGS_MODULE=blockauth.settings.staging
    depends_on:
      - db
      - redis

volumes:
  postgres_data:
  redis_data:
```

#### 2. Smart Contract Deployment

**Hardhat Configuration for Staging:**
```javascript
// hardhat.config.js
require("@nomicfoundation/hardhat-toolbox");
require("@openzeppelin/hardhat-upgrades");
require("dotenv").config();

module.exports = {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000000
      }
    }
  },
  networks: {
    sepolia: {
      url: `https://sepolia.infura.io/v3/${process.env.INFURA_API_KEY}`,
      accounts: [process.env.PRIVATE_KEY],
      gasPrice: 20000000000, // 20 gwei
      gasLimit: 8000000
    }
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY
  }
};
```

**Deployment Script:**
```javascript
// scripts/deploy-staging.js
const { ethers, upgrades } = require("hardhat");

async function main() {
  console.log("Deploying contracts to Sepolia...");

  // Deploy SmartAccount implementation
  const SmartAccount = await ethers.getContractFactory("SmartAccount");
  const smartAccountImpl = await SmartAccount.deploy(
    "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789" // EntryPoint address
  );
  await smartAccountImpl.deployed();
  console.log("SmartAccount implementation:", smartAccountImpl.address);

  // Deploy SmartAccountFactory
  const SmartAccountFactory = await ethers.getContractFactory("SmartAccountFactory");
  const factory = await SmartAccountFactory.deploy(smartAccountImpl.address);
  await factory.deployed();
  console.log("SmartAccountFactory:", factory.address);

  // Deploy Paymaster
  const BlockAuthPaymaster = await ethers.getContractFactory("BlockAuthPaymaster");
  const paymaster = await upgrades.deployProxy(
    BlockAuthPaymaster,
    ["0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"],
    { initializer: "initialize" }
  );
  await paymaster.deployed();
  console.log("BlockAuthPaymaster:", paymaster.address);

  // Fund paymaster
  const [deployer] = await ethers.getSigners();
  const fundTx = await deployer.sendTransaction({
    to: paymaster.address,
    value: ethers.utils.parseEther("1.0") // Fund with 1 ETH
  });
  await fundTx.wait();
  console.log("Paymaster funded with 1 ETH");

  // Verify contracts
  console.log("Verifying contracts...");
  await hre.run("verify:verify", {
    address: smartAccountImpl.address,
    constructorArguments: ["0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"]
  });

  await hre.run("verify:verify", {
    address: factory.address,
    constructorArguments: [smartAccountImpl.address]
  });

  console.log("Deployment completed!");
  console.log("Update your .env with the following addresses:");
  console.log(`AA_FACTORY_ADDRESS=${factory.address}`);
  console.log(`AA_PAYMASTER_ADDRESS=${paymaster.address}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
```

#### 3. Deploy to Staging
```bash
# Build and deploy containers
docker-compose -f docker-compose.staging.yml build
docker-compose -f docker-compose.staging.yml up -d

# Deploy smart contracts
npx hardhat run scripts/deploy-staging.js --network sepolia

# Run database migrations
docker-compose exec web python manage.py migrate

# Collect static files
docker-compose exec web python manage.py collectstatic --noinput

# Load initial data
docker-compose exec web python manage.py loaddata fixtures/initial_data.json
```

## Production Deployment

### Infrastructure Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   Web Servers    │    │   Databases     │
│   (AWS ALB/     │───▶│   (ECS/K8s)      │───▶│   (RDS/Redis)   │
│    Cloudflare)  │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌──────────────────┐             │
         │              │   Background     │             │
         └──────────────│   Workers        │─────────────┘
                        │   (Celery)       │
                        └──────────────────┘
                                 │
                        ┌──────────────────┐
                        │   Monitoring     │
                        │   (DataDog/      │
                        │    Prometheus)   │
                        └──────────────────┘
```

### AWS Deployment

#### 1. Infrastructure as Code (Terraform)

**terraform/main.tf:**
```hcl
provider "aws" {
  region = "us-east-1"
}

# VPC Configuration
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "blockauth-aa-vpc"
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "blockauth-aa-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# RDS Instance
resource "aws_db_instance" "main" {
  identifier = "blockauth-aa-db"
  
  engine         = "postgres"
  engine_version = "13.7"
  instance_class = "db.t3.medium"
  
  allocated_storage     = 100
  max_allocated_storage = 1000
  
  db_name  = "blockauth"
  username = "blockauth"
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "Sun:04:00-Sun:05:00"
  
  deletion_protection = true
  skip_final_snapshot = false
  
  tags = {
    Name = "blockauth-aa-db"
  }
}

# ElastiCache Redis
resource "aws_elasticache_replication_group" "main" {
  replication_group_id         = "blockauth-aa-redis"
  description                  = "Redis cluster for BlockAuth AA"
  
  num_cache_clusters         = 3
  node_type                  = "cache.t3.medium"
  parameter_group_name       = "default.redis6.x"
  
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.main.name
  security_group_ids         = [aws_security_group.redis.id]
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  
  tags = {
    Name = "blockauth-aa-redis"
  }
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "blockauth-aa-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets           = aws_subnet.public[*].id

  enable_deletion_protection = true

  tags = {
    Name = "blockauth-aa-alb"
  }
}
```

#### 2. ECS Task Definition

**ecs/task-definition.json:**
```json
{
  "family": "blockauth-aa-web",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "web",
      "image": "blockauth/aa-web:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "DJANGO_SETTINGS_MODULE",
          "value": "blockauth.settings.production"
        },
        {
          "name": "AA_NETWORK",
          "value": "mainnet"
        }
      ],
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "/blockauth/production/database-url"
        },
        {
          "name": "SECRET_KEY",
          "valueFrom": "/blockauth/production/secret-key"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/blockauth-aa",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "curl -f http://localhost:8000/health/ || exit 1"
        ],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      }
    }
  ]
}
```

#### 3. Smart Contract Production Deployment

**Mainnet Deployment Script:**
```javascript
// scripts/deploy-production.js
const { ethers, upgrades } = require("hardhat");

async function main() {
  console.log("Deploying to Ethereum Mainnet...");
  
  // Verify we're on mainnet
  const network = await ethers.provider.getNetwork();
  if (network.chainId !== 1) {
    throw new Error("This script should only be run on mainnet");
  }

  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  
  const balance = await deployer.getBalance();
  console.log("Account balance:", ethers.utils.formatEther(balance), "ETH");
  
  if (balance.lt(ethers.utils.parseEther("5.0"))) {
    throw new Error("Insufficient balance for deployment");
  }

  // Deploy with create2 for deterministic addresses
  const create2Factory = await ethers.getContractAt(
    "Create2Factory",
    "0x4e59b44847b379578588920cA78FbF26c0B4956C"
  );

  // Deploy SmartAccount implementation
  const SmartAccount = await ethers.getContractFactory("SmartAccount");
  const smartAccountSalt = ethers.utils.solidityKeccak256(
    ["string"],
    ["BlockAuth_SmartAccount_v1.0.0"]
  );
  
  const smartAccountImpl = await create2Factory.deploy(
    SmartAccount.bytecode,
    smartAccountSalt,
    { gasLimit: 5000000 }
  );
  
  console.log("SmartAccount implementation:", smartAccountImpl.address);

  // Deploy Factory
  const SmartAccountFactory = await ethers.getContractFactory("SmartAccountFactory");
  const factorySalt = ethers.utils.solidityKeccak256(
    ["string"],
    ["BlockAuth_Factory_v1.0.0"]
  );
  
  const factory = await create2Factory.deploy(
    SmartAccountFactory.bytecode + 
    ethers.utils.defaultAbiCoder.encode(["address"], [smartAccountImpl.address]).slice(2),
    factorySalt,
    { gasLimit: 3000000 }
  );
  
  console.log("SmartAccountFactory:", factory.address);

  // Deploy Paymaster with proxy pattern
  const BlockAuthPaymaster = await ethers.getContractFactory("BlockAuthPaymaster");
  const paymaster = await upgrades.deployProxy(
    BlockAuthPaymaster,
    ["0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"],
    {
      initializer: "initialize",
      gasLimit: 8000000
    }
  );
  await paymaster.deployed();
  
  console.log("BlockAuthPaymaster:", paymaster.address);

  // Fund paymaster with 10 ETH
  const fundTx = await deployer.sendTransaction({
    to: paymaster.address,
    value: ethers.utils.parseEther("10.0"),
    gasLimit: 21000
  });
  await fundTx.wait();
  
  console.log("Paymaster funded with 10 ETH");

  // Set up multi-sig as owner
  const multisigAddress = "0x..."; // Your multi-sig address
  await paymaster.transferOwnership(multisigAddress, { gasLimit: 100000 });
  
  console.log("Ownership transferred to multi-sig:", multisigAddress);

  // Save deployment info
  const deploymentInfo = {
    network: "mainnet",
    chainId: 1,
    entryPoint: "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",
    smartAccountImpl: smartAccountImpl.address,
    factory: factory.address,
    paymaster: paymaster.address,
    deployer: deployer.address,
    timestamp: new Date().toISOString(),
    gasUsed: {
      smartAccount: smartAccountImpl.deployTransaction?.gasUsed?.toString(),
      factory: factory.deployTransaction?.gasUsed?.toString(),
      paymaster: paymaster.deployTransaction?.gasUsed?.toString()
    }
  };
  
  console.log("Deployment completed successfully!");
  console.log(JSON.stringify(deploymentInfo, null, 2));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
```

### Kubernetes Deployment

#### 1. Kubernetes Manifests

**k8s/namespace.yaml:**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: blockauth-aa
```

**k8s/deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blockauth-aa-web
  namespace: blockauth-aa
spec:
  replicas: 3
  selector:
    matchLabels:
      app: blockauth-aa-web
  template:
    metadata:
      labels:
        app: blockauth-aa-web
    spec:
      containers:
      - name: web
        image: blockauth/aa-web:latest
        ports:
        - containerPort: 8000
        env:
        - name: DJANGO_SETTINGS_MODULE
          value: "blockauth.settings.production"
        envFrom:
        - secretRef:
            name: blockauth-aa-secrets
        resources:
          limits:
            cpu: "1000m"
            memory: "2Gi"
          requests:
            cpu: "500m"
            memory: "1Gi"
        livenessProbe:
          httpGet:
            path: /health/
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready/
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

**k8s/service.yaml:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: blockauth-aa-web-service
  namespace: blockauth-aa
spec:
  selector:
    app: blockauth-aa-web
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
  type: ClusterIP
```

**k8s/ingress.yaml:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: blockauth-aa-ingress
  namespace: blockauth-aa
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  tls:
  - hosts:
    - api.blockauth.io
    secretName: blockauth-aa-tls
  rules:
  - host: api.blockauth.io
    http:
      paths:
      - path: /api/aa
        pathType: Prefix
        backend:
          service:
            name: blockauth-aa-web-service
            port:
              number: 80
```

#### 2. Deploy to Kubernetes
```bash
# Apply manifests
kubectl apply -f k8s/

# Wait for deployment
kubectl rollout status deployment/blockauth-aa-web -n blockauth-aa

# Check pod status
kubectl get pods -n blockauth-aa

# View logs
kubectl logs -f deployment/blockauth-aa-web -n blockauth-aa
```

## Monitoring and Observability

### 1. Application Monitoring

**DataDog Configuration:**
```python
# blockauth/settings/production.py
INSTALLED_APPS += [
    'ddtrace.contrib.django',
]

MIDDLEWARE = [
    'ddtrace.contrib.django.DjangoTraceMiddleware',
] + MIDDLEWARE

# DataDog settings
DATADOG_TRACE = {
    'DEFAULT_SERVICE': 'blockauth-aa',
    'TAGS': {
        'env': 'production',
        'version': '1.0.0'
    }
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'datadog': {
            'level': 'INFO',
            'class': 'ddtrace.contrib.logging.StreamHandler',
        }
    },
    'loggers': {
        'blockauth.aa': {
            'handlers': ['datadog'],
            'level': 'INFO',
            'propagate': True,
        }
    }
}
```

### 2. Infrastructure Monitoring

**Prometheus Configuration:**
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'blockauth-aa'
    static_configs:
      - targets: ['blockauth-aa-web:8000']
    metrics_path: /metrics/
    scrape_interval: 5s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
```

**Grafana Dashboard:**
```json
{
  "dashboard": {
    "id": null,
    "title": "BlockAuth Account Abstraction",
    "panels": [
      {
        "title": "User Operations per Second",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(aa_user_operations_total[5m])",
            "legendFormat": "{{status}}"
          }
        ]
      },
      {
        "title": "Gas Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(aa_gas_usage_total[5m])",
            "legendFormat": "{{sponsored}}"
          }
        ]
      }
    ]
  }
}
```

## Security Considerations

### 1. Smart Contract Security

- **Multi-signature wallet** as contract owner
- **Timelock contract** for upgrades
- **Access control** for all admin functions
- **Rate limiting** on bundler operations
- **Gas limit** validation
- **Signature** replay protection

### 2. API Security

```python
# Security middleware configuration
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'blockauth.middleware.RateLimitMiddleware',
    'blockauth.middleware.AASecurityMiddleware',
] + MIDDLEWARE

# Security settings
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_HSTS_SECONDS = 31536000
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True

# Rate limiting
RATELIMIT_USE_CACHE = 'default'
RATELIMIT_ENABLE = True

# CORS settings
CORS_ALLOWED_ORIGINS = [
    "https://app.blockauth.io",
]
```

### 3. Infrastructure Security

- **VPC** with private subnets
- **Security groups** with least privilege
- **WAF** for DDoS protection
- **Secrets management** with AWS Secrets Manager
- **Container scanning** for vulnerabilities
- **Network segmentation**
- **Backup encryption**

## Rollback Procedures

### 1. Application Rollback
```bash
# ECS rollback
aws ecs update-service \
  --cluster blockauth-aa-cluster \
  --service blockauth-aa-web \
  --task-definition blockauth-aa-web:PREVIOUS_REVISION

# Kubernetes rollback
kubectl rollout undo deployment/blockauth-aa-web -n blockauth-aa
```

### 2. Database Rollback
```bash
# Restore from backup
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier blockauth-aa-db-rollback \
  --db-snapshot-identifier blockauth-aa-db-snapshot-20231101
```

### 3. Smart Contract Emergency Procedures
- **Pause contract** functions if exploit detected
- **Emergency withdrawal** from paymaster
- **Transfer ownership** to emergency multi-sig
- **Contact bundler services** to halt operations

## Post-Deployment Checklist

### 1. Functional Testing
- [ ] Smart account creation works
- [ ] User operations execute successfully
- [ ] Paymaster sponsors gas correctly
- [ ] Batch operations function
- [ ] Recovery mechanisms work
- [ ] Session keys operate correctly

### 2. Performance Testing
- [ ] API response times < 500ms
- [ ] Database queries optimized
- [ ] Bundler response times acceptable
- [ ] System handles expected load

### 3. Security Verification
- [ ] All endpoints require authentication
- [ ] Rate limiting active
- [ ] SSL certificates valid
- [ ] Security headers present
- [ ] Input validation working
- [ ] Audit logs capturing events

### 4. Monitoring Setup
- [ ] Application metrics collecting
- [ ] Infrastructure monitoring active
- [ ] Alerts configured
- [ ] Dashboard accessible
- [ ] Log aggregation working

This deployment guide ensures a secure, scalable, and maintainable deployment of the BlockAuth Account Abstraction system across all environments.