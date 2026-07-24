from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Any

# Authentication
class SetupAdminModel(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8)

class LoginModel(BaseModel):
    email: EmailStr
    password: str

class UpdateProfileModel(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=2, max_length=100)

# User Management (RBAC)
class UserSaveModel(BaseModel):
    id: Optional[str] = None
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    role: str = Field(..., pattern="^(admin|analyst|viewer|responder)$")
    department: str = Field(..., min_length=2, max_length=100)
    status: str = Field(..., pattern="^(active|inactive)$")
    permissions: Optional[List[str]] = None
    password: Optional[str] = None

# Reports
class ReportCreateModel(BaseModel):
    id: str
    name: str = Field(..., min_length=1, max_length=200)
    type: str
    date: str
    startDate: str
    endDate: str
    pages: int = Field(..., ge=1)
    size: str
    data: Optional[Any] = None

# Settings
class ProfileModel(BaseModel):
    name: str
    email: EmailStr
    role: str

class IntegrationModel(BaseModel):
    name: str
    connected: bool

class SettingsSaveModel(BaseModel):
    notifyOnCritical: bool
    notifyOnHigh: bool
    dailySummary: bool
    criticalThreshold: int = Field(..., ge=0, le=100)
    highThreshold: int = Field(..., ge=0, le=100)
    mediumThreshold: int = Field(..., ge=0, le=100)
    profile: ProfileModel
    integrations: List[IntegrationModel]

# SOAR Automation Rules
class RuleSaveModel(BaseModel):
    id: Optional[str] = "RULE-01"
    name: Optional[str] = "Rule"
    description: Optional[str] = ""
    trigger: Optional[str] = "automatic"
    action: Optional[str] = "block"
    severity: Optional[str] = "high"
    enabled: Optional[bool] = True
    lastFired: Optional[str] = None
    firedCount: Optional[int] = 0
    category: Optional[str] = "containment"
    threshold: Optional[int] = 20
    time_window: Optional[str] = "10s"
