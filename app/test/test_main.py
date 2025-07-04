import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_read_main():
    response = client.get("/")
    assert response.status_code == 200
    assert "Email Validator API" in response.json()["message"]

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_api_docs():
    response = client.get("/docs")
    assert response.status_code == 200

def test_redoc():
    response = client.get("/redoc")
    assert response.status_code == 200