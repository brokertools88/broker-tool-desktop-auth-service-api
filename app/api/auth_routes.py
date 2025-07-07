"""
InsureCove Authentication Service - Authentication Routes

RESTful authentication endpoints following 2024 standards:
- POST /auth/brokers (create broker account)
- POST /auth/clients (create client account)
- POST /auth/sessions (login/authenticate)
- GET /auth/sessions/current (get current session)
- DELETE /auth/sessions (logout)
- POST /auth/tokens/refresh (refresh access token)
- POST /auth/tokens/verify (verify token)
- POST /auth/password/change (change password)
- POST /auth/password/reset (request password reset)
- POST /auth/password/reset/confirm (confirm password reset)
"""

from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials

from app.core import (
    auth_dependency,
    security_logger,
    api_logger,
    InvalidCredentialsException,
    UserAlreadyExistsException,
    TokenExpiredException,
    TokenInvalidException,
    UserNotFoundException,
    WeakPasswordException,
    PasswordMismatchException,
    get_settings
)

from app.auth.auth_adapter import AuthManagerAdapter
from app.models import (
    BrokerCreateRequest,
    ClientCreateRequest,
    LoginRequest,
    TokenRefreshRequest,
    TokenVerifyRequest,
    LogoutRequest,
    PasswordChangeRequest,
    PasswordResetRequest,
    PasswordResetConfirmRequest,
    LoginResponse,
    UserCreateResponse,
    SessionResponse,
    TokenResponse,
    TokenVerifyResponse,
    UserResponse,
    ResponseModel
)

# Initialize router
router = APIRouter()

# Initialize settings
settings = get_settings()

# Initialize auth manager
auth_manager = AuthManagerAdapter()


# Rate limiting decorator (if available)
def rate_limit(requests_per_minute: int = 60):
    """Rate limiting decorator"""
    def decorator(func):
        try:
            from slowapi import Limiter
            from slowapi.util import get_remote_address
            
            limiter = Limiter(key_func=get_remote_address)
            return limiter.limit(f"{requests_per_minute}/minute")(func)
        except ImportError:
            # Rate limiting not available, return function as-is
            return func
    return decorator


def get_client_info(request: Request) -> Dict[str, str]:
    """Extract client information from request"""
    return {
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown")
    }


@router.post(
    "/brokers",
    response_model=UserCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create broker account",
    description="Create a new broker account with company information"
)
@rate_limit(requests_per_minute=10)  # Stricter rate limit for registration
async def create_broker(
    broker_data: BrokerCreateRequest,
    request: Request
) -> UserCreateResponse:
    """Create a new broker account"""
    
    if not settings.enable_registration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is currently disabled"
        )
    
    client_info = get_client_info(request)
    
    try:
        # Create broker account
        user = await auth_manager.create_broker(
            email=broker_data.email,
            password=broker_data.password,
            first_name=broker_data.first_name,
            last_name=broker_data.last_name,
            phone=broker_data.phone,
            company_name=broker_data.company_name,
            license_number=broker_data.license_number
        )
        
        # Log successful registration
        security_logger.log_security_event(
            event_type="user_registration",
            user_id=user.id,
            details={
                "user_type": "broker",
                "email": broker_data.email,
                "company_name": broker_data.company_name
            },
            **client_info
        )
        
        api_logger.info(
            f"Broker account created: {broker_data.email}",
            extra={
                "user_id": user.id,
                "user_type": "broker",
                **client_info
            }
        )
        
        return UserCreateResponse(
            message="Broker account created successfully",
            user=user,
            verification_required=settings.enable_email_verification
        )
        
    except UserAlreadyExistsException as e:
        security_logger.log_security_event(
            event_type="registration_attempt_existing_user",
            details={"email": broker_data.email},
            **client_info
        )
        raise e
    
    except WeakPasswordException as e:
        raise e
    
    except Exception as e:
        api_logger.error(
            f"Failed to create broker account: {str(e)}",
            extra={
                "email": broker_data.email,
                **client_info
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create account"
        )


@router.post(
    "/clients",
    response_model=UserCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create client account",
    description="Create a new client account"
)
@rate_limit(requests_per_minute=10)
async def create_client(
    client_data: ClientCreateRequest,
    request: Request
) -> UserCreateResponse:
    """Create a new client account"""
    
    if not settings.enable_registration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is currently disabled"
        )
    
    client_info = get_client_info(request)
    
    try:
        # Create client account
        user = await auth_manager.create_client(
            email=client_data.email,
            password=client_data.password,
            first_name=client_data.first_name,
            last_name=client_data.last_name,
            phone=client_data.phone,
            date_of_birth=client_data.date_of_birth,
            address=client_data.address
        )
        
        # Log successful registration
        security_logger.log_security_event(
            event_type="user_registration",
            user_id=user.id,
            details={
                "user_type": "client",
                "email": client_data.email
            },
            **client_info
        )
        
        api_logger.info(
            f"Client account created: {client_data.email}",
            extra={
                "user_id": user.id,
                "user_type": "client",
                **client_info
            }
        )
        
        return UserCreateResponse(
            message="Client account created successfully",
            user=user,
            verification_required=settings.enable_email_verification
        )
        
    except UserAlreadyExistsException as e:
        security_logger.log_security_event(
            event_type="registration_attempt_existing_user",
            details={"email": client_data.email},
            **client_info
        )
        raise e
    
    except WeakPasswordException as e:
        raise e
    
    except Exception as e:
        api_logger.error(
            f"Failed to create client account: {str(e)}",
            extra={
                "email": client_data.email,
                **client_info
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create account"
        )


@router.post(
    "/sessions",
    response_model=LoginResponse,
    summary="Login/Authenticate",
    description="Authenticate user and create session"
)
@rate_limit(requests_per_minute=20)
async def login(
    login_data: LoginRequest,
    request: Request
) -> LoginResponse:
    """Authenticate user and create session"""
    
    client_info = get_client_info(request)
    
    try:
        # Authenticate user
        auth_result = await auth_manager.authenticate_user(
            email=login_data.email,
            password=login_data.password,
            remember_me=login_data.remember_me
        )
        
        # Log successful login
        security_logger.log_login_attempt(
            email=login_data.email,
            success=True,
            **client_info
        )
        
        api_logger.info(
            f"User logged in: {login_data.email}",
            extra={
                "user_id": auth_result["user"].id,
                **client_info
            }
        )
        
        return LoginResponse(
            message="Login successful",
            tokens=auth_result["tokens"],
            user=auth_result["user"],
            session_id=auth_result["session_id"]
        )
        
    except InvalidCredentialsException as e:
        security_logger.log_login_attempt(
            email=login_data.email,
            success=False,
            **client_info
        )
        raise e
    
    except Exception as e:
        api_logger.error(
            f"Login failed: {str(e)}",
            extra={
                "email": login_data.email,
                **client_info
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )


@router.get(
    "/sessions/current",
    response_model=SessionResponse,
    summary="Get current session",
    description="Get information about the current authenticated session"
)
async def get_current_session(
    current_user: Dict[str, Any] = Depends(auth_dependency),
    request: Request = None
) -> SessionResponse:
    """Get current session information"""
    
    try:
        # Get user details
        user = await auth_manager.get_user_by_id(current_user["user_id"])
        
        # Get session info
        session_info = await auth_manager.get_session_info(current_user["user_id"])
        
        return SessionResponse(
            user=user,
            session_id=session_info["session_id"],
            expires_at=session_info["expires_at"],
            permissions=current_user.get("permissions", [])
        )
        
    except UserNotFoundException as e:
        raise e
    
    except Exception as e:
        api_logger.error(
            f"Failed to get session info: {str(e)}",
            extra={
                "user_id": current_user.get("user_id"),
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve session information"
        )


@router.delete(
    "/sessions",
    response_model=ResponseModel,
    summary="Logout",
    description="Logout user and invalidate session"
)
async def logout(
    logout_data: LogoutRequest,
    current_user: Dict[str, Any] = Depends(auth_dependency),
    request: Request = None
) -> ResponseModel:
    """Logout user and invalidate session"""
    
    client_info = get_client_info(request)
    
    try:
        # Logout user
        await auth_manager.logout_user(
            user_id=current_user["user_id"],
            refresh_token=logout_data.refresh_token,
            logout_all_devices=logout_data.logout_all_devices
        )
        
        # Log logout
        security_logger.log_security_event(
            event_type="user_logout",
            user_id=current_user["user_id"],
            details={
                "logout_all_devices": logout_data.logout_all_devices
            },
            **client_info
        )
        
        api_logger.info(
            "User logged out",
            extra={
                "user_id": current_user["user_id"],
                **client_info
            }
        )
        
        return ResponseModel(message="Logout successful")
        
    except Exception as e:
        api_logger.error(
            f"Logout failed: {str(e)}",
            extra={
                "user_id": current_user.get("user_id"),
                **client_info
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.post(
    "/tokens/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Refresh access token using refresh token"
)
@rate_limit(requests_per_minute=30)
async def refresh_token(
    refresh_data: TokenRefreshRequest,
    request: Request
) -> TokenResponse:
    """Refresh access token"""
    
    client_info = get_client_info(request)
    
    try:
        # Refresh token
        tokens = await auth_manager.refresh_access_token(refresh_data.refresh_token)
        
        # Log token refresh
        security_logger.log_token_creation(
            user_id=tokens.get("user_id"),
            token_type="access",
            **client_info
        )
        
        return TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            expires_in=tokens["expires_in"]
        )
        
    except (TokenExpiredException, TokenInvalidException) as e:
        security_logger.log_token_validation(
            success=False,
            token_type="refresh",
            error=str(e),
            **client_info
        )
        raise e
    
    except Exception as e:
        api_logger.error(
            f"Token refresh failed: {str(e)}",
            extra=client_info
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )


@router.post(
    "/tokens/verify",
    response_model=TokenVerifyResponse,
    summary="Verify token",
    description="Verify and decode a JWT token"
)
async def verify_token(
    verify_data: TokenVerifyRequest,
    request: Request
) -> TokenVerifyResponse:
    """Verify a JWT token"""
    
    client_info = get_client_info(request)
    
    try:
        # Verify token
        result = await auth_manager.verify_token(
            token=verify_data.token,
            token_type=verify_data.token_type
        )
        
        # Log token verification
        security_logger.log_token_validation(
            success=result["valid"],
            token_type=verify_data.token_type.value,
            **client_info
        )
        
        return TokenVerifyResponse(**result)
        
    except (TokenExpiredException, TokenInvalidException) as e:
        security_logger.log_token_validation(
            success=False,
            token_type=verify_data.token_type.value,
            error=str(e),
            **client_info
        )
        
        # Return invalid response instead of raising exception
        return TokenVerifyResponse(
            valid=False,
            token_type=verify_data.token_type,
            expires_at=None
        )
    
    except Exception as e:
        api_logger.error(
            f"Token verification failed: {str(e)}",
            extra=client_info
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token verification failed"
        )


@router.post(
    "/password/change",
    response_model=ResponseModel,
    summary="Change password",
    description="Change user password"
)
async def change_password(
    password_data: PasswordChangeRequest,
    current_user: Dict[str, Any] = Depends(auth_dependency),
    request: Request = None
) -> ResponseModel:
    """Change user password"""
    
    client_info = get_client_info(request)
    
    try:
        # Change password
        await auth_manager.change_password(
            user_id=current_user["user_id"],
            current_password=password_data.current_password,
            new_password=password_data.new_password
        )
        
        # Log password change
        security_logger.log_security_event(
            event_type="password_change",
            user_id=current_user["user_id"],
            details={},
            **client_info
        )
        
        api_logger.info(
            "Password changed successfully",
            extra={
                "user_id": current_user["user_id"],
                **client_info
            }
        )
        
        return ResponseModel(message="Password changed successfully")
        
    except (InvalidCredentialsException, WeakPasswordException, PasswordMismatchException) as e:
        raise e
    
    except Exception as e:
        api_logger.error(
            f"Password change failed: {str(e)}",
            extra={
                "user_id": current_user.get("user_id"),
                **client_info
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )


@router.post(
    "/password/reset",
    response_model=ResponseModel,
    summary="Request password reset",
    description="Request a password reset email"
)
@rate_limit(requests_per_minute=5)  # Very strict rate limit
async def request_password_reset(
    reset_data: PasswordResetRequest,
    request: Request
) -> ResponseModel:
    """Request password reset"""
    
    if not settings.enable_password_reset:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password reset is currently disabled"
        )
    
    client_info = get_client_info(request)
    
    try:
        # Request password reset
        await auth_manager.request_password_reset(reset_data.email)
        
        # Log password reset request
        security_logger.log_security_event(
            event_type="password_reset_request",
            details={"email": reset_data.email},
            **client_info
        )
        
        # Always return success to prevent email enumeration
        return ResponseModel(
            message="If an account with that email exists, a password reset link has been sent"
        )
        
    except Exception as e:
        api_logger.error(
            f"Password reset request failed: {str(e)}",
            extra={
                "email": reset_data.email,
                **client_info
            }
        )
        
        # Still return success to prevent information leakage
        return ResponseModel(
            message="If an account with that email exists, a password reset link has been sent"
        )


@router.post(
    "/password/reset/confirm",
    response_model=ResponseModel,
    summary="Confirm password reset",
    description="Confirm password reset with token"
)
@rate_limit(requests_per_minute=5)
async def confirm_password_reset(
    confirm_data: PasswordResetConfirmRequest,
    request: Request
) -> ResponseModel:
    """Confirm password reset"""
    
    if not settings.enable_password_reset:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password reset is currently disabled"
        )
    
    client_info = get_client_info(request)
    
    try:
        # Confirm password reset
        user_id = await auth_manager.confirm_password_reset(
            token=confirm_data.token,
            new_password=confirm_data.new_password
        )
        
        # Log password reset completion
        security_logger.log_security_event(
            event_type="password_reset_completed",
            user_id=user_id,
            details={},
            **client_info
        )
        
        api_logger.info(
            "Password reset completed",
            extra={
                "user_id": user_id,
                **client_info
            }
        )
        
        return ResponseModel(message="Password reset successful")
        
    except (TokenExpiredException, TokenInvalidException, WeakPasswordException) as e:
        raise e
    
    except Exception as e:
        api_logger.error(
            f"Password reset confirmation failed: {str(e)}",
            extra=client_info
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset failed"
        ) 