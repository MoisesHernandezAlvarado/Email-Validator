from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from enum import Enum

class ValidationLevel(str, Enum):
    FORMAT_ONLY = "format_only"
    BASIC = "basic"
    ADVANCED = "advanced"
    FULL = "full"

class EmailRequest(BaseModel):
    email: str = Field(..., description="Dirección de correo electrónico a validar")
    check_domain: bool = Field(True, description="Verificar si el dominio existe")
    check_mx: bool = Field(True, description="Verificar registros MX del dominio")
    check_smtp: bool = Field(False, description="Verificar conexión SMTP (lento)")
    
    @validator('email')
    def validate_email_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('El email no puede estar vacío')
        return v.strip().lower()

class SMTPValidationResult(BaseModel):
    exists: bool = False
    deliverable: bool = False
    mailbox_full: bool = False
    catch_all: bool = False
    smtp_code: Optional[int] = None
    smtp_message: str = ""
    details: List[str] = Field(default_factory=list)

class EmailValidationResult(BaseModel):
    email: str
    is_valid: bool
    format_valid: bool
    domain_exists: bool
    mx_record_exists: bool
    smtp_valid: Optional[bool] = None
    smtp_details: Optional[SMTPValidationResult] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    validation_time: Optional[float] = None
    domain_info: Optional[dict] = None

class BatchEmailRequest(BaseModel):
    emails: List[str] = Field(..., max_items=100, description="Lista de emails a validar")
    check_domain: bool = Field(True, description="Verificar si el dominio existe")
    check_mx: bool = Field(True, description="Verificar registros MX del dominio")
    check_smtp: bool = Field(False, description="Verificar conexión SMTP (lento)")
    
    @validator('emails')
    def validate_emails_not_empty(cls, v):
        if not v:
            raise ValueError('La lista de emails no puede estar vacía')
        if len(v) > 100:
            raise ValueError('Máximo 100 emails por lote')
        return [email.strip().lower() for email in v if email.strip()]

class BatchEmailResult(BaseModel):
    total: int
    valid: int
    invalid: int
    processing_time: float
    results: List[EmailValidationResult]
    summary: dict = Field(default_factory=dict)

class DomainInfo(BaseModel):
    domain: str
    exists: bool
    has_mx: bool
    mx_records: List[str] = Field(default_factory=list)
    a_records: List[str] = Field(default_factory=list)
    last_checked: Optional[str] = None

class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    code: Optional[int] = None