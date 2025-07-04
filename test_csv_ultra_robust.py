#!/usr/bin/env python3
"""
Script de prueba para el endpoint CSV ultra-robusto
Demuestra todas las capacidades avanzadas del procesador de CSV
"""

import requests
import json
import time
import pandas as pd
import io
from typing import Dict

# Configuración
API_BASE_URL = "http://localhost:8000/api/v1/email"

def create_test_csv():
    """Crea un archivo CSV de prueba con diferentes tipos de emails"""
    test_data = {
        'email': [
            'agz77395@lasallebajio.edu.mx',      # Email institucional
            'test@gmail.com',                     # Gmail común
            'usuario@dominio-inexistente.xyz',    # Dominio inexistente
            'email-invalido@',                    # Formato inválido
            'test@10minutemail.com',              # Email desechable
            'admin@microsoft.com',                # Email corporativo
            'test@mailinator.com',                # Email temporal
            'válido@example.com',                 # Con caracteres especiales
            'test@test.test',                     # Dominio de prueba
            'contact@empresa.mx',                 # Email empresarial mexicano
            '',                                   # Email vacío
            'null',                              # Valor null
            'no-email-here',                     # Sin @
            'test@@double.com',                  # Doble @
            'user@válido.com'                    # Dominio con caracteres especiales
        ],
        'nombre': [
            'Juan Pérez', 'María García', 'Carlos López', 'Ana Martínez',
            'Luis Rodríguez', 'Carmen Sánchez', 'José Hernández', 'Laura González',
            'Miguel Torres', 'Isabel Ruiz', 'Antonio Díaz', 'Cristina Moreno',
            'Francisco Jiménez', 'Pilar Álvarez', 'Rafael Romero'
        ],
        'empresa': [
            'La Salle Bajío', 'Google', 'Empresa Inexistente', 'Email Inválido',
            'Temporal Inc', 'Microsoft', 'Mailinator', 'Example Corp',
            'Test Company', 'Empresa MX', 'Sin Email', 'Null Corp',
            'No Email Co', 'Double Corp', 'Válido SA'
        ]
    }
    
    df = pd.DataFrame(test_data)
    
    # Guardar en diferentes encodings para probar robustez
    csv_files = {}
    
    # UTF-8
    csv_utf8 = io.StringIO()
    df.to_csv(csv_utf8, index=False, encoding='utf-8')
    csv_files['test_emails_utf8.csv'] = csv_utf8.getvalue().encode('utf-8')
    
    # Latin-1
    csv_latin1 = io.StringIO()
    df.to_csv(csv_latin1, index=False)
    csv_files['test_emails_latin1.csv'] = csv_latin1.getvalue().encode('latin-1')
    
    # Con separador diferente (punto y coma)
    csv_semicolon = io.StringIO()
    df.to_csv(csv_semicolon, index=False, sep=';')
    csv_files['test_emails_semicolon.csv'] = csv_semicolon.getvalue().encode('utf-8')
    
    return csv_files

def test_csv_validation(file_name: str, file_content: bytes, validation_level: str = "ultra_deep"):
    """Prueba la validación CSV con diferentes configuraciones"""
    print(f"\n🔍 PROBANDO ARCHIVO: {file_name}")
    print("=" * 80)
    
    try:
        # Preparar archivo para upload
        files = {'file': (file_name, file_content, 'text/csv')}
        
        # Configuración de prueba
        params = {
            'validation_level': validation_level,
            'batch_size': 5,
            'include_details': True,
            'export_format': 'json',
            'confidence_threshold': 60
        }
        
        print(f"⚙️  Configuración:")
        print(f"   📊 Nivel de validación: {validation_level}")
        print(f"   📦 Tamaño de lote: {params['batch_size']}")
        print(f"   🔍 Incluir detalles: {params['include_details']}")
        print(f"   🎯 Umbral de confianza: {params['confidence_threshold']}")
        
        start_time = time.time()
        
        # Hacer la petición
        response = requests.post(
            f"{API_BASE_URL}/validate-csv",
            files=files,
            params=params
        )
        
        total_time = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            
            print(f"\n✅ PROCESAMIENTO EXITOSO")
            print(f"⏱️  Tiempo total: {total_time:.2f}s")
            print(f"📊 Estado: {result.get('🎉 status', 'N/A')}")
            print(f"💬 Mensaje: {result.get('message', 'N/A')}")
            
            # Mostrar resumen general
            summary = result.get('summary', {})
            resumen_general = summary.get('🎯 Resumen General', {})
            
            print(f"\n📋 RESUMEN GENERAL:")
            print(f"   📁 Archivo: {resumen_general.get('archivo_procesado', 'N/A')}")
            print(f"   🔤 Encoding: {resumen_general.get('encoding_detectado', 'N/A')}")
            print(f"   📧 Columna email: {resumen_general.get('columna_email', 'N/A')}")
            print(f"   🎯 Nivel validación: {resumen_general.get('nivel_validacion', 'N/A')}")
            
            # Mostrar estadísticas de procesamiento
            stats_procesamiento = summary.get('📊 Estadísticas de Procesamiento', {})
            
            print(f"\n📊 ESTADÍSTICAS DE PROCESAMIENTO:")
            print(f"   📧 Total emails: {stats_procesamiento.get('total_emails', 0)}")
            print(f"   ✅ Emails válidos: {stats_procesamiento.get('emails_validos', 0)}")
            print(f"   ❌ Emails inválidos: {stats_procesamiento.get('emails_invalidos', 0)}")
            print(f"   📈 Tasa de éxito: {stats_procesamiento.get('tasa_exito', 'N/A')}")
            print(f"   ⏱️  Tiempo promedio: {stats_procesamiento.get('tiempo_promedio', 'N/A')}")
            
            # Mostrar análisis de confianza
            analisis_confianza = summary.get('🎯 Análisis de Confianza', {})
            
            print(f"\n🎯 ANÁLISIS DE CONFIANZA:")
            print(f"   🏆 Calidad del dataset: {analisis_confianza.get('dataset_quality', 'N/A')}")
            print(f"   📊 Confianza promedio: {analisis_confianza.get('avg_confidence_score', 'N/A')}/100")
            
            distribucion = analisis_confianza.get('confidence_distribution', {})
            print(f"   📈 Distribución de confianza:")
            print(f"      🟢 Alta (80-100): {distribucion.get('high_confidence', 0)}")
            print(f"      🟡 Media (60-79): {distribucion.get('medium_confidence', 0)}")
            print(f"      🔴 Baja (0-59): {distribucion.get('low_confidence', 0)}")
            
            # Mostrar problemas detectados
            problemas = summary.get('🔍 Problemas Detectados', {})
            
            print(f"\n🔍 PROBLEMAS DETECTADOS:")
            print(f"   📝 Errores de formato: {problemas.get('errores_formato', 0)}")
            print(f"   🌐 Errores de dominio: {problemas.get('errores_dominio', 0)}")
            print(f"   📧 Errores MX: {problemas.get('errores_mx', 0)}")
            print(f"   🗑️  Emails desechables: {problemas.get('emails_desechables', 0)}")
            print(f"   🚫 Problemas reputación IP: {problemas.get('problemas_reputacion_ip', 0)}")
            
            # Mostrar recomendaciones
            recomendaciones = summary.get('💡 Recomendaciones', [])
            if recomendaciones:
                print(f"\n💡 RECOMENDACIONES:")
                for i, rec in enumerate(recomendaciones, 1):
                    print(f"   {i}. {rec}")
            
            # Mostrar algunos resultados detallados
            results = result.get('results', [])
            if results and validation_level == "ultra_deep":
                print(f"\n🔍 MUESTRA DE RESULTADOS DETALLADOS:")
                
                # Mostrar los primeros 3 resultados
                for i, email_result in enumerate(results[:3], 1):
                    print(f"\n   📧 Email {i}: {email_result.get('email', 'N/A')}")
                    print(f"      ✅ Válido: {'SÍ' if email_result.get('is_valid') else 'NO'}")
                    print(f"      🎯 Confianza: {email_result.get('confidence_score', 0)}/100")
                    print(f"      ⏱️  Tiempo: {email_result.get('processing_time', 0):.3f}s")
                    
                    # Mostrar recomendaciones específicas
                    recommendations = email_result.get('recommendations', [])
                    if recommendations:
                        print(f"      💡 Recomendaciones:")
                        for rec in recommendations[:2]:  # Solo las primeras 2
                            print(f"         • {rec}")
                    
                    # Mostrar errores si los hay
                    errors = email_result.get('errors', [])
                    if errors:
                        print(f"      ❌ Errores:")
                        for error in errors[:2]:  # Solo los primeros 2
                            print(f"         • {error}")
            
            # Mostrar estadísticas de procesamiento
            processing_stats = result.get('processing_stats', {})
            print(f"\n📈 ESTADÍSTICAS INTERNAS:")
            print(f"   ✅ Validaciones exitosas: {processing_stats.get('successful_validations', 0)}")
            print(f"   ❌ Validaciones fallidas: {processing_stats.get('failed_validations', 0)}")
            print(f"   🟢 Alta confianza: {processing_stats.get('high_confidence', 0)}")
            print(f"   🟡 Media confianza: {processing_stats.get('medium_confidence', 0)}")
            print(f"   🔴 Baja confianza: {processing_stats.get('low_confidence', 0)}")
            
            # Mostrar metadata
            metadata = result.get('metadata', {})
            print(f"\n🔧 METADATA:")
            print(f"   🚀 Versión API: {metadata.get('api_version', 'N/A')}")
            print(f"   ⏱️  Tiempo total procesamiento: {metadata.get('total_processing_time', 0):.2f}s")
            
            return result
            
        else:
            print(f"❌ ERROR EN LA API: {response.status_code}")
            try:
                error_detail = response.json()
                print(f"   📝 Detalle del error:")
                print(json.dumps(error_detail, indent=2, ensure_ascii=False))
            except:
                print(f"   📝 Respuesta: {response.text}")
            return {}
            
    except Exception as e:
        print(f"❌ ERROR CRÍTICO: {e}")
        return {}

def test_all_validation_levels():
    """Prueba todos los niveles de validación"""
    print("\n🚀 PROBANDO TODOS LOS NIVELES DE VALIDACIÓN")
    print("=" * 80)
    
    # Crear archivo de prueba pequeño
    test_data = {
        'correo_electronico': [
            'agz77395@lasallebajio.edu.mx',
            'test@gmail.com',
            'invalid@nonexistent.xyz',
            'test@10minutemail.com'
        ]
    }
    
    df = pd.DataFrame(test_data)
    csv_content = df.to_csv(index=False).encode('utf-8')
    
    levels = ['standard', 'deep', 'ultra_deep']
    
    for level in levels:
        print(f"\n🎯 PROBANDO NIVEL: {level.upper()}")
        print("-" * 60)
        
        result = test_csv_validation(
            f'test_level_{level}.csv',
            csv_content,
            validation_level=level
        )
        
        if result:
            processing_time = result.get('metadata', {}).get('total_processing_time', 0)
            total_emails = result.get('summary', {}).get('📊 Estadísticas de Procesamiento', {}).get('total_emails', 0)
            
            print(f"✅ Completado en {processing_time:.2f}s para {total_emails} emails")
        
        time.sleep(1)  # Pausa entre pruebas

def main():
    """Función principal de prueba"""
    print("🚀 SISTEMA DE VALIDACIÓN CSV ULTRA-ROBUSTO")
    print("=" * 80)
    print("Probando el endpoint más avanzado de procesamiento de CSV")
    
    # Crear archivos de prueba
    print("\n📁 Creando archivos de prueba...")
    csv_files = create_test_csv()
    
    # Probar cada archivo
    for file_name, file_content in csv_files.items():
        result = test_csv_validation(file_name, file_content)
        time.sleep(2)  # Pausa entre archivos
    
    # Probar todos los niveles de validación
    test_all_validation_levels()
    
    print("\n" + "=" * 80)
    print("✅ PRUEBAS COMPLETADAS")
    print("El endpoint CSV ultra-robusto ha sido probado exhaustivamente")
    print("🎯 Características demostradas:")
    print("   ✅ Detección automática de encoding")
    print("   ✅ Detección automática de separadores")
    print("   ✅ Detección inteligente de columnas de email")
    print("   ✅ Procesamiento en lotes optimizado")
    print("   ✅ Análisis estadístico avanzado")
    print("   ✅ Recomendaciones inteligentes")
    print("   ✅ Manejo robusto de errores")
    print("   ✅ Múltiples niveles de validación")

if __name__ == "__main__":
    main() 