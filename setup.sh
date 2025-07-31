#!/bin/bash

# Security-Enhanced Setup Script for Agentic AI Industry Use Cases
# This script follows security best practices and includes comprehensive validation

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate Python version
validate_python() {
    log "Validating Python installation..."
    
    if ! command_exists python3; then
        log_error "Python 3 is not installed. Please install Python 3.8 or higher."
        exit 1
    fi
    
    # Check Python version
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    required_version="3.8"
    
    if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
        log_error "Python ${python_version} detected. Python 3.8 or higher is required."
        exit 1
    fi
    
    log_success "Python ${python_version} detected - compatible version"
}

# Function to validate pip and upgrade if needed
validate_pip() {
    log "Validating pip installation..."
    
    if ! command_exists pip3; then
        log_error "pip3 is not installed. Please install pip3."
        exit 1
    fi
    
    # Upgrade pip to latest version for security
    log "Upgrading pip to latest version..."
    python3 -m pip install --upgrade pip --quiet
    
    log_success "pip validated and upgraded"
}

# Function to create virtual environment
setup_virtual_environment() {
    log "Setting up virtual environment..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        log "Creating virtual environment..."
        python3 -m venv venv
        log_success "Virtual environment created"
    else
        log_warning "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    log "Activating virtual environment..."
    source venv/bin/activate
    
    # Upgrade pip in virtual environment
    pip install --upgrade pip --quiet
    
    log_success "Virtual environment activated"
}

# Function to install secure dependencies
install_dependencies() {
    log "Installing secure Python dependencies..."
    
    # Determine which requirements file to use
    local requirements_file=""
    
    # Check for project-specific secure requirements
    if [ -f "retail/requirements_secure.txt" ]; then
        requirements_file="retail/requirements_secure.txt"
        log "Using retail-specific secure requirements"
    elif [ -f "insurance/requirements_secure.txt" ]; then
        requirements_file="insurance/requirements_secure.txt"
        log "Using insurance-specific secure requirements"
    elif [ -f "finance/requirements_secure.txt" ]; then
        requirements_file="finance/requirements_secure.txt"
        log "Using finance-specific secure requirements"
    elif [ -f "requirements.txt" ]; then
        requirements_file="requirements.txt"
        log_warning "Using general requirements.txt - consider using secure requirements"
    else
        log_error "No requirements file found. Please ensure requirements.txt exists."
        exit 1
    fi
    
    # Install dependencies with security checks
    log "Installing dependencies from ${requirements_file}..."
    pip install -r "${requirements_file}" --upgrade --no-cache-dir
    
    # Install security scanning tools
    log "Installing security scanning tools..."
    pip install --upgrade bandit safety pip-audit --quiet
    
    log_success "Dependencies installed successfully"
}

# Function to run security scans
run_security_scans() {
    log "Running security scans on installed packages..."
    
    # Check for known vulnerabilities in dependencies
    log "Scanning for known vulnerabilities..."
    if command_exists safety; then
        if ! safety check --json --output /tmp/safety_report.json 2>/dev/null; then
            log_warning "Some packages may have known vulnerabilities. Check /tmp/safety_report.json"
        else
            log_success "No known vulnerabilities found in dependencies"
        fi
    fi
    
    # Audit packages for security issues
    if command_exists pip-audit; then
        log "Running pip-audit security scan..."
        if ! pip-audit --format=json --output=/tmp/pip_audit_report.json 2>/dev/null; then
            log_warning "pip-audit found potential issues. Check /tmp/pip_audit_report.json"
        else
            log_success "pip-audit scan completed successfully"
        fi
    fi
}

# Function to validate AWS CLI
validate_aws_cli() {
    log "Validating AWS CLI installation..."
    
    if ! command_exists aws; then
        log_warning "AWS CLI not found. Installing AWS CLI..."
        pip install awscli --upgrade --quiet
        log_success "AWS CLI installed"
    else
        # Check AWS CLI version
        aws_version=$(aws --version 2>&1 | cut -d/ -f2 | cut -d' ' -f1)
        log_success "AWS CLI ${aws_version} detected"
    fi
}

# Function to configure AWS CLI securely
configure_aws_cli() {
    log "Configuring AWS CLI..."
    
    # Check if AWS credentials are already configured
    if aws sts get-caller-identity >/dev/null 2>&1; then
        log_success "AWS credentials already configured and valid"
        
        # Display current AWS identity (without sensitive info)
        aws_identity=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || echo "Unknown")
        log "Current AWS Account: ${aws_identity}"
    else
        log_warning "AWS credentials not configured or invalid"
        log "Please configure AWS CLI with your credentials..."
        log "You can use: aws configure"
        log "Or set environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY"
        
        # Prompt user for configuration
        read -p "Would you like to configure AWS CLI now? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            aws configure
            
            # Validate configuration
            if aws sts get-caller-identity >/dev/null 2>&1; then
                log_success "AWS CLI configured successfully"
            else
                log_error "AWS CLI configuration failed"
                exit 1
            fi
        else
            log_warning "AWS CLI not configured. Some features may not work."
        fi
    fi
}

# Function to set up secure environment variables
setup_environment_variables() {
    log "Setting up secure environment variables..."
    
    # Create .env file if it doesn't exist
    if [ ! -f ".env" ]; then
        log "Creating .env file with secure defaults..."
        cat > .env << EOF
# AWS Configuration
AWS_REGION=us-east-1
AWS_DEFAULT_REGION=us-east-1

# Bedrock Configuration
BEDROCK_AGENT_CORE_ENDPOINT=https://bedrock-agent-runtime.us-east-1.amazonaws.com
BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0

# Security Configuration
ENVIRONMENT=development
DEBUG=false
LOG_LEVEL=INFO

# Database Configuration (use environment-specific values)
# POSTGRES_SERVER=localhost
# POSTGRES_PORT=5432
# POSTGRES_DB=your_database
# POSTGRES_USER=your_user
# POSTGRES_PASSWORD=your_secure_password

# Redis Configuration
# REDIS_HOST=localhost
# REDIS_PORT=6379

# JWT Configuration (generate secure keys for production)
# JWT_SECRET_KEY=your_very_long_and_secure_secret_key_here
# ENCRYPTION_KEY=your_encryption_key_here

# Security Settings
MAX_REQUEST_SIZE=5242880
SESSION_TIMEOUT_MINUTES=15
MAX_LOGIN_ATTEMPTS=3
PASSWORD_MIN_LENGTH=14

EOF
        log_success ".env file created with secure defaults"
        log_warning "Please update .env file with your specific configuration values"
    else
        log_warning ".env file already exists - not overwriting"
    fi
    
    # Export essential environment variables for current session
    export AWS_REGION=${AWS_REGION:-us-east-1}
    export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1}
    export BEDROCK_AGENT_CORE_ENDPOINT=${BEDROCK_AGENT_CORE_ENDPOINT:-https://bedrock-agent-runtime.us-east-1.amazonaws.com}
    
    log_success "Environment variables configured"
}

# Function to display security recommendations
display_security_recommendations() {
    log "Security Recommendations:"
    echo
    echo "🔒 SECURITY CHECKLIST:"
    echo "  ✅ Use secure requirements files (requirements_secure.txt)"
    echo "  ✅ Keep dependencies updated regularly"
    echo "  ✅ Use environment variables for sensitive configuration"
    echo "  ✅ Enable SSL/TLS in production"
    echo "  ✅ Use strong, unique passwords and API keys"
    echo "  ✅ Regularly run security scans (bandit, safety, pip-audit)"
    echo "  ✅ Follow principle of least privilege for AWS IAM"
    echo "  ✅ Enable AWS CloudTrail and monitoring"
    echo "  ✅ Use AWS Secrets Manager for sensitive data"
    echo "  ✅ Implement proper logging and monitoring"
    echo
    echo "📚 SECURITY RESOURCES:"
    echo "  - OWASP Top 10: https://owasp.org/www-project-top-ten/"
    echo "  - AWS Security Best Practices: https://aws.amazon.com/security/security-resources/"
    echo "  - Python Security: https://python-security.readthedocs.io/"
    echo
}

# Main setup function
main() {
    log "🚀 Starting Security-Enhanced Setup for Agentic AI Industry Use Cases"
    echo "=================================================================="
    
    # Validate system requirements
    validate_python
    validate_pip
    
    # Set up Python environment
    setup_virtual_environment
    
    # Install dependencies securely
    install_dependencies
    
    # Run security scans
    run_security_scans
    
    # Configure AWS
    validate_aws_cli
    configure_aws_cli
    
    # Set up environment
    setup_environment_variables
    
    # Display security recommendations
    display_security_recommendations
    
    echo "=================================================================="
    log_success "🎉 Setup completed successfully!"
    log_success "🔒 Security-enhanced environment is ready"
    log_success "🤖 You can now use the agentic AI agents securely"
    echo
    log "Next steps:"
    echo "  1. Review and update .env file with your configuration"
    echo "  2. Ensure AWS credentials are properly configured"
    echo "  3. Run security scans regularly: bandit -r . && safety check"
    echo "  4. Follow security best practices in development"
    echo
    log "For retail inventory management: cd retail && python src/main_final_secure.py"
    log "For insurance claims processing: cd insurance && python src/main.py"
    log "For finance applications: cd finance && python src/main.py"
}

# Error handling
trap 'log_error "Setup failed at line $LINENO. Exit code: $?"' ERR

# Run main setup
main "$@"