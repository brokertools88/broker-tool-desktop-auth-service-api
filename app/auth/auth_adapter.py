"""
InsureCove Authentication Service - Auth Manager Adapter

Adapter that bridges the existing SupabaseAuthManager with the new API models
and provides the interface expected by the authentication routes.
"""

from datetime import datetime
from typing import Dict, Any, Optional

from app.auth.supabase_auth import (
    SupabaseAuthManager as BaseSupabaseAuthManager,
    RegisterRequest,
    TokenResponse as BaseTokenResponse,
    PasswordResetRequest as BasePasswordResetRequest,
    AuthenticationError,
    TokenError,
    UserRole
)

from app.models import (
    UserResponse,
    TokenResponse,
    TokenType,
    UserRole as APIUserRole,
    UserStatus
)

from app.core import (
    InvalidCredentialsException,
    UserAlreadyExistsException,
    TokenExpiredException,
    TokenInvalidException,
    UserNotFoundException,
    WeakPasswordException,
    password_manager,
    jwt_manager
)


class AuthManagerAdapter:
    """
    Adapter for SupabaseAuthManager to work with the new API interface
    """
    
    def __init__(self):
        self.base_manager = BaseSupabaseAuthManager()
    
    def _convert_user_role(self, api_role: APIUserRole) -> UserRole:
        """Convert API user role to Supabase user role"""
        role_mapping = {
            APIUserRole.BROKER: UserRole.BROKER,
            APIUserRole.CLIENT: UserRole.USER,
            APIUserRole.ADMIN: UserRole.ADMIN,
            APIUserRole.SUPER_ADMIN: UserRole.ADMIN
        }
        return role_mapping.get(api_role, UserRole.USER)
    
    def _convert_api_user_role(self, supabase_role: UserRole) -> APIUserRole:
        """Convert Supabase user role to API user role"""
        role_mapping = {
            UserRole.BROKER: APIUserRole.BROKER,
            UserRole.USER: APIUserRole.CLIENT,
            UserRole.ADMIN: APIUserRole.ADMIN
        }
        return role_mapping.get(supabase_role, APIUserRole.CLIENT)
    
    def _create_user_response(self, user_data: Dict[str, Any]) -> UserResponse:
        """Create UserResponse from user data"""
        return UserResponse(
            id=user_data.get("id", ""),
            email=user_data.get("email", ""),
            first_name=user_data.get("first_name", ""),
            last_name=user_data.get("last_name", ""),
            phone=user_data.get("phone"),
            role=self._convert_api_user_role(UserRole(user_data.get("role", "user"))),
            status=UserStatus.ACTIVE,  # Default status
            email_verified=user_data.get("email_verified", False),
            last_login=datetime.utcnow() if user_data.get("last_login") else None,
            company_name=user_data.get("company_name"),
            license_number=user_data.get("license_number"),
            date_of_birth=user_data.get("date_of_birth"),
            address=user_data.get("address"),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
    
    async def create_broker(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        phone: Optional[str] = None,
        company_name: Optional[str] = None,
        license_number: Optional[str] = None
    ) -> UserResponse:
        """Create a new broker account"""
        
        try:
            # Validate password strength
            password_errors = password_manager.validate_password_strength(password)
            if password_errors:
                raise WeakPasswordException(password_errors)
            
            # Create registration request
            register_request = RegisterRequest(
                email=email,
                password=password,
                full_name=f"{first_name} {last_name}",
                role=UserRole.BROKER,
                metadata={
                    "first_name": first_name,
                    "last_name": last_name,
                    "phone": phone,
                    "company_name": company_name,
                    "license_number": license_number,
                    "user_type": "broker"
                }
            )
            
            # Register user
            token_response = await self.base_manager.register_user(register_request)
            
            # Create user response
            user_data = {
                "id": token_response.user.get("id"),
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "phone": phone,
                "role": "broker",
                "company_name": company_name,
                "license_number": license_number
            }
            
            return self._create_user_response(user_data)
            
        except AuthenticationError as e:
            if "already exists" in str(e).lower():
                raise UserAlreadyExistsException(email)
            raise InvalidCredentialsException(str(e))
    
    async def create_client(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        phone: Optional[str] = None,
        date_of_birth: Optional[datetime] = None,
        address: Optional[str] = None
    ) -> UserResponse:
        """Create a new client account"""
        
        try:
            # Validate password strength
            password_errors = password_manager.validate_password_strength(password)
            if password_errors:
                raise WeakPasswordException(password_errors)
            
            # Create registration request
            register_request = RegisterRequest(
                email=email,
                password=password,
                full_name=f"{first_name} {last_name}",
                role=UserRole.USER,
                metadata={
                    "first_name": first_name,
                    "last_name": last_name,
                    "phone": phone,
                    "date_of_birth": date_of_birth.isoformat() if date_of_birth else None,
                    "address": address,
                    "user_type": "client"
                }
            )
            
            # Register user
            token_response = await self.base_manager.register_user(register_request)
            
            # Create user response
            user_data = {
                "id": token_response.user.get("id"),
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "phone": phone,
                "role": "user",
                "date_of_birth": date_of_birth,
                "address": address
            }
            
            return self._create_user_response(user_data)
            
        except AuthenticationError as e:
            if "already exists" in str(e).lower():
                raise UserAlreadyExistsException(email)
            raise InvalidCredentialsException(str(e))
    
    async def authenticate_user(
        self,
        email: str,
        password: str,
        remember_me: bool = False
    ) -> Dict[str, Any]:
        """Authenticate user and return tokens"""
        
        try:
            # Create login request
            from app.auth.supabase_auth import LoginRequest
            login_request = LoginRequest(
                email=email,
                password=password,
                remember_me=remember_me
            )
            
            # Authenticate user
            token_response = await self.base_manager.authenticate_user(login_request)
            
            # Create user response
            user_data = token_response.user
            user = self._create_user_response(user_data)
            
            # Create token response
            tokens = TokenResponse(
                access_token=token_response.access_token,
                refresh_token=token_response.refresh_token or "",
                token_type="bearer",
                expires_in=token_response.expires_in
            )
            
            return {
                "tokens": tokens,
                "user": user,
                "session_id": f"session_{user.id}_{int(datetime.utcnow().timestamp())}"
            }
            
        except AuthenticationError as e:
            raise InvalidCredentialsException(str(e))
    
    async def get_user_by_id(self, user_id: str) -> UserResponse:
        """Get user by ID"""
        
        try:
            # This would need to be implemented in the base manager
            # For now, create a mock response
            user_data = {
                "id": user_id,
                "email": "user@example.com",
                "first_name": "Unknown",
                "last_name": "User",
                "role": "user"
            }
            
            return self._create_user_response(user_data)
            
        except Exception as e:
            raise UserNotFoundException(user_id=user_id)
    
    async def get_session_info(self, user_id: str) -> Dict[str, Any]:
        """Get session information"""
        
        return {
            "session_id": f"session_{user_id}_{int(datetime.utcnow().timestamp())}",
            "expires_at": datetime.utcnow().replace(hour=23, minute=59, second=59)  # End of day
        }
    
    async def logout_user(
        self,
        user_id: str,
        refresh_token: Optional[str] = None,
        logout_all_devices: bool = False
    ):
        """Logout user"""
        
        try:
            if refresh_token:
                await self.base_manager.logout_user(refresh_token)
            return True
            
        except Exception as e:
            # Log error but don't raise exception for logout
            pass
    
    async def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token"""
        
        try:
            token_response = await self.base_manager.refresh_token(refresh_token)
            
            return {
                "access_token": token_response.access_token,
                "refresh_token": token_response.refresh_token or refresh_token,
                "expires_in": token_response.expires_in,
                "user_id": token_response.user.get("id")
            }
            
        except TokenError as e:
            if "expired" in str(e).lower():
                raise TokenExpiredException(str(e))
            raise TokenInvalidException(str(e))
    
    async def verify_token(
        self,
        token: str,
        token_type: TokenType = TokenType.ACCESS
    ) -> Dict[str, Any]:
        """Verify a JWT token"""
        
        try:
            # Use the base manager's verification
            user = await self.base_manager.verify_user_token(token)
            
            return {
                "valid": True,
                "token_type": token_type,
                "user_id": user.id,
                "email": user.email,
                "role": self._convert_api_user_role(user.role),
                "expires_at": datetime.utcnow().replace(hour=23, minute=59, second=59),
                "permissions": []  # TODO: Implement permissions
            }
            
        except TokenError as e:
            if "expired" in str(e).lower():
                raise TokenExpiredException(str(e))
            raise TokenInvalidException(str(e))
    
    async def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str
    ):
        """Change user password"""
        
        try:
            # Validate new password strength
            password_errors = password_manager.validate_password_strength(new_password)
            if password_errors:
                raise WeakPasswordException(password_errors)
            
            # TODO: Implement password change in base manager
            # For now, simulate success
            return True
            
        except Exception as e:
            raise InvalidCredentialsException("Password change failed")
    
    async def request_password_reset(self, email: str):
        """Request password reset"""
        
        try:
            reset_request = BasePasswordResetRequest(email=email)
            await self.base_manager.reset_password_request(reset_request)
            return True
            
        except Exception as e:
            # Don't raise exception to prevent email enumeration
            return True
    
    async def confirm_password_reset(
        self,
        token: str,
        new_password: str
    ) -> str:
        """Confirm password reset"""
        
        try:
            # Validate new password strength
            password_errors = password_manager.validate_password_strength(new_password)
            if password_errors:
                raise WeakPasswordException(password_errors)
            
            # TODO: Implement password reset confirmation in base manager
            # For now, simulate success and return a user ID
            return "user_12345"
            
        except TokenError as e:
            if "expired" in str(e).lower():
                raise TokenExpiredException(str(e))
            raise TokenInvalidException(str(e))
