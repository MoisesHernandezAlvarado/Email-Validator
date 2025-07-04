import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.email_service import EmailValidationService

client = TestClient(app)

class TestEmailValidation:
    
    def test_validate_email_format_valid(self):
        """Test validación de formato válido"""
        assert EmailValidationService.validate_email_format("test@example.com") == True
        assert EmailValidationService.validate_email_format("user.name@domain.co.uk") == True
        assert EmailValidationService.validate_email_format("user+tag@example.org") == True
    
    def test_validate_email_format_invalid(self):
        """Test validación de formato inválido"""
        assert EmailValidationService.validate_email_format("invalid-email") == False
        assert EmailValidationService.validate_email_format("@example.com") == False
        assert EmailValidationService.validate_email_format("user@") == False
        assert EmailValidationService.validate_email_format("user..name@example.com") == False
    
    def test_validate_simple_endpoint(self):
        """Test endpoint de validación simple"""
        response = client.get("/api/v1/email/validate-simple/test@example.com")
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["is_valid"] == True
        assert data["validation_type"] == "format_only"
    
    def test_validate_simple_endpoint_invalid(self):
        """Test endpoint de validación simple con email inválido"""
        response = client.get("/api/v1/email/validate-simple/invalid-email")
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "invalid-email"
        assert data["is_valid"] == False
    
    def test_validate_email_complete(self):
        """Test validación completa"""
        response = client.post(
            "/api/v1/email/validate",
            json={
                "email": "test@gmail.com",
                "check_domain": True,
                "check_mx": True,
                "check_smtp": False
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "is_valid" in data
        assert "format_valid" in data
        assert "domain_exists" in data
        assert "mx_record_exists" in data
    
    def test_validate_email_batch(self):
        """Test validación por lotes"""
        response = client.post(
            "/api/v1/email/validate-batch",
            json={
                "emails": ["test1@gmail.com", "test2@yahoo.com", "invalid-email"],
                "check_domain": True,
                "check_mx": True,
                "check_smtp": False
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3
        assert "valid" in data
        assert "invalid" in data
        assert "empty" in data
        assert "duplicates" in data
        assert "invalid_format" in data
        assert "valid_format" in data
        assert "cleaned_emails" in data
        assert "invalid_emails" in data
        assert "common_domains" in data