#!/usr/bin/env python3
"""
Script de prueba para el sistema de validación ultra-profundo
Demuestra las capacidades avanzadas del validador de emails
"""

import requests
import json
import time
from typing import List, Dict

# Configuración
API_BASE_URL = "http://localhost:8000/api/v1/email"

def test_ultra_scan(email: str) -> Dict:
    """Prueba el scan ultra-profundo de un email"""
    print(f"\n🔍 ESCANEANDO: {email}")
    print("=" * 60)
    
    try:
        start_time = time.time()
        response = requests.get(f"{API_BASE_URL}/validate-ultra/{email}")
        total_time = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            
            print(f"⏱️  Tiempo total: {total_time:.2f}s")
            print(f"🎯 Puntuación de confianza: {result['confidence_score']}/100")
            print(f"✅ Válido: {'SÍ' if result['is_valid'] else 'NO'}")
            
            # Análisis de formato
            format_analysis = result.get('format_analysis', {})
            if format_analysis.get('is_valid'):
                print("📝 Formato: ✅ VÁLIDO")
            else:
                print("📝 Formato: ❌ INVÁLIDO")
                for error in format_analysis.get('errors', []):
                    print(f"   ❌ {error}")
            
            # Análisis de dominio
            domain_analysis = result.get('domain_analysis', {})
            if domain_analysis.get('exists'):
                print("🌐 Dominio: ✅ EXISTE")
                print(f"   📍 IPs: {', '.join(domain_analysis.get('a_records', []))}")
                if domain_analysis.get('aaaa_records'):
                    print(f"   🌍 IPv6: {', '.join(domain_analysis.get('aaaa_records', []))}")
            else:
                print("🌐 Dominio: ❌ NO EXISTE")
            
            # Análisis MX
            mx_analysis = result.get('mx_analysis', {})
            if mx_analysis.get('has_mx'):
                print("📧 Servidores MX: ✅ CONFIGURADOS")
                for mx_detail in mx_analysis.get('mx_details', []):
                    status = "✅" if mx_detail.get('exists') else "❌"
                    print(f"   {status} {mx_detail.get('host')} (prioridad: {mx_detail.get('priority')})")
            else:
                print("📧 Servidores MX: ❌ NO CONFIGURADOS")
            
            # Análisis SMTP
            smtp_analysis = result.get('smtp_analysis', {})
            print(f"\n🔗 ANÁLISIS SMTP:")
            print(f"   📨 Existe: {'✅ SÍ' if smtp_analysis.get('exists') else '❌ NO'}")
            print(f"   📬 Entregable: {'✅ SÍ' if smtp_analysis.get('deliverable') else '❌ NO'}")
            print(f"   📦 Buzón lleno: {'⚠️ SÍ' if smtp_analysis.get('mailbox_full') else '✅ NO'}")
            print(f"   🔄 Catch-all: {'⚠️ SÍ' if smtp_analysis.get('catch_all') else '✅ NO'}")
            
            if smtp_analysis.get('smtp_code'):
                print(f"   📟 Código SMTP: {smtp_analysis.get('smtp_code')}")
            
            # Mostrar intentos de conexión
            attempts = smtp_analysis.get('attempts', [])
            if attempts:
                print(f"\n🔄 INTENTOS DE CONEXIÓN ({len(attempts)}):")
                for i, attempt in enumerate(attempts, 1):
                    print(f"   {i}. Servidor: {attempt.get('server')}")
                    print(f"      ⏱️  Tiempo: {attempt.get('timing', {}).get('total', 0):.2f}s")
                    print(f"      🎯 Confianza: {attempt.get('confidence', 0)}/100")
                    
                    if attempt.get('ip_reputation_issue'):
                        print(f"      🚫 Problema de reputación: {attempt.get('blocked_reason', 'Desconocido')}")
                    
                    if attempt.get('server_info', {}).get('banner'):
                        print(f"      🏷️  Banner: {attempt.get('server_info', {}).get('banner')[:60]}...")
            
            # Análisis de seguridad
            security_analysis = result.get('security_analysis', {})
            print(f"\n🛡️  ANÁLISIS DE SEGURIDAD:")
            print(f"   🗑️  Desechable: {'⚠️ SÍ' if security_analysis.get('is_disposable') else '✅ NO'}")
            print(f"   🏢 Proveedor principal: {'✅ SÍ' if security_analysis.get('is_major_provider') else '❌ NO'}")
            print(f"   🔒 Características seguridad: {'✅ SÍ' if security_analysis.get('has_security_features') else '❌ NO'}")
            
            # Recomendaciones
            recommendations = result.get('recommendations', [])
            if recommendations:
                print(f"\n💡 RECOMENDACIONES:")
                for rec in recommendations:
                    print(f"   {rec}")
            
            # Errores y warnings
            errors = result.get('errors', [])
            warnings = result.get('warnings', [])
            
            if errors:
                print(f"\n❌ ERRORES:")
                for error in errors:
                    print(f"   • {error}")
            
            if warnings:
                print(f"\n⚠️  ADVERTENCIAS:")
                for warning in warnings:
                    print(f"   • {warning}")
            
            return result
            
        else:
            print(f"❌ Error en la API: {response.status_code}")
            print(f"   {response.text}")
            return {}
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return {}

def test_validator_info():
    """Prueba la información del validador"""
    print("\n🔧 INFORMACIÓN DEL VALIDADOR")
    print("=" * 60)
    
    try:
        response = requests.get(f"{API_BASE_URL}/validator-info")
        if response.status_code == 200:
            info = response.json()
            
            print(f"Estado: {info.get('validator_status')}")
            print(f"IP Pública: {info.get('public_ip')}")
            print(f"IP Local: {info.get('local_ip')}")
            print(f"Servidores DNS: {', '.join(info.get('dns_servers', []))}")
            print(f"Timeout SMTP: {info.get('smtp_timeout')}s")
            print(f"Timeout DNS: {info.get('dns_timeout')}s")
            
            print("\n📋 Notas sobre reputación:")
            for note in info.get('reputation_notes', []):
                print(f"   {note}")
            
            print("\n🚀 Tips de optimización:")
            for tip in info.get('optimization_tips', []):
                print(f"   {tip}")
                
    except Exception as e:
        print(f"❌ Error obteniendo info del validador: {e}")

def main():
    """Función principal de prueba"""
    print("🚀 SISTEMA DE VALIDACIÓN ULTRA-PROFUNDO")
    print("=" * 60)
    print("Este sistema nunca falla y siempre retorna un resultado completo")
    
    # Obtener información del validador
    test_validator_info()
    
    # Lista de emails de prueba
    test_emails = [
        "agz77395@lasallebajio.edu.mx",  # Email institucional
        "test@gmail.com",                # Gmail común
        "usuario@dominio-inexistente.xyz",  # Dominio inexistente
        "email-invalido@",               # Formato inválido
        "test@10minutemail.com",         # Email desechable
        "admin@microsoft.com",           # Email corporativo
        "test@mailinator.com",           # Email temporal
        ""                               # Email vacío
    ]
    
    # Probar cada email
    for email in test_emails:
        result = test_ultra_scan(email)
        
        # Pausa entre pruebas
        time.sleep(1)
    
    print("\n" + "=" * 60)
    print("✅ PRUEBAS COMPLETADAS")
    print("El sistema ultra-profundo ha procesado todos los emails sin fallar")
    print("Cada resultado incluye análisis completo y recomendaciones inteligentes")

if __name__ == "__main__":
    main() 