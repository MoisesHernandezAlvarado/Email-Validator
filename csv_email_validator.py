#!/usr/bin/env python3
"""
Script para validar emails desde un archivo CSV usando la API de validación
"""

import csv
import json
import requests
import pandas as pd
from datetime import datetime
import argparse
import sys
from typing import List, Dict, Any
import time

class CSVEmailValidator:
    def __init__(self, api_base_url: str = "http://localhost:8000"):
        self.api_base_url = api_base_url
        self.api_endpoint = f"{api_base_url}/api/v1/email"
        
    def validate_single_email(self, email: str, check_domain: bool = True, 
                            check_mx: bool = True, check_smtp: bool = False) -> Dict[str, Any]:
        """Valida un email individual usando la API"""
        try:
            payload = {
                "email": email,
                "check_domain": check_domain,
                "check_mx": check_mx,
                "check_smtp": check_smtp
            }
            
            response = requests.post(
                f"{self.api_endpoint}/validate",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    "email": email,
                    "is_valid": False,
                    "format_valid": False,
                    "domain_exists": False,
                    "mx_record_exists": False,
                    "errors": [f"Error API: {response.status_code}"],
                    "warnings": [],
                    "validation_time": 0
                }
                
        except requests.exceptions.RequestException as e:
            return {
                "email": email,
                "is_valid": False,
                "format_valid": False,
                "domain_exists": False,
                "mx_record_exists": False,
                "errors": [f"Error de conexión: {str(e)}"],
                "warnings": [],
                "validation_time": 0
            }
    
    def validate_batch_emails(self, emails: List[str], check_domain: bool = True,
                            check_mx: bool = True, check_smtp: bool = False) -> Dict[str, Any]:
        """Valida emails en lote usando la API"""
        try:
            payload = {
                "emails": emails,
                "check_domain": check_domain,
                "check_mx": check_mx,
                "check_smtp": check_smtp
            }
            
            response = requests.post(
                f"{self.api_endpoint}/validate-batch",
                json=payload,
                timeout=120
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error en lote: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"Error de conexión en lote: {e}")
            return None
    
    def read_csv(self, file_path: str, email_column: str = None) -> List[str]:
        """Lee emails desde un archivo CSV"""
        try:
            df = pd.read_csv(file_path)
            
            # Si no se especifica columna, buscar automáticamente
            if email_column is None:
                # Buscar columnas que contengan 'email', 'correo', 'mail'
                email_cols = [col for col in df.columns if any(
                    keyword in col.lower() for keyword in ['email', 'correo', 'mail']
                )]
                
                if email_cols:
                    email_column = email_cols[0]
                    print(f"📧 Usando columna: '{email_column}'")
                else:
                    print("❌ No se encontró columna de email. Columnas disponibles:")
                    for i, col in enumerate(df.columns):
                        print(f"  {i}: {col}")
                    return []
            
            # Validar que la columna existe
            if email_column not in df.columns:
                print(f"❌ Columna '{email_column}' no encontrada")
                return []
            
            # Extraer emails y limpiar
            emails = df[email_column].dropna().astype(str).tolist()
            emails = [email.strip() for email in emails if email.strip()]
            
            print(f"📊 Encontrados {len(emails)} emails en el CSV")
            return emails
            
        except Exception as e:
            print(f"❌ Error leyendo CSV: {e}")
            return []
    
    def process_csv(self, csv_file: str, output_file: str = None, 
                   email_column: str = None, batch_size: int = 50,
                   check_domain: bool = True, check_mx: bool = True, 
                   check_smtp: bool = False) -> Dict[str, Any]:
        """Procesa un archivo CSV completo"""
        
        print(f"🚀 Iniciando validación de emails desde: {csv_file}")
        start_time = time.time()
        
        # Leer emails del CSV
        emails = self.read_csv(csv_file, email_column)
        if not emails:
            return {"error": "No se pudieron leer emails del CSV"}
        
        all_results = []
        total_emails = len(emails)
        
        # Procesar en lotes
        for i in range(0, total_emails, batch_size):
            batch = emails[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (total_emails + batch_size - 1) // batch_size
            
            print(f"📦 Procesando lote {batch_num}/{total_batches} ({len(batch)} emails)")
            
            # Intentar validación en lote
            batch_result = self.validate_batch_emails(batch, check_domain, check_mx, check_smtp)
            
            if batch_result and 'results' in batch_result:
                all_results.extend(batch_result['results'])
                print(f"✅ Lote {batch_num} completado")
            else:
                # Si falla el lote, procesar individualmente
                print(f"⚠️  Lote {batch_num} falló, procesando individualmente...")
                for email in batch:
                    result = self.validate_single_email(email, check_domain, check_mx, check_smtp)
                    all_results.append(result)
                    time.sleep(0.1)  # Pequeña pausa entre requests individuales
        
        # Calcular estadísticas
        total_time = time.time() - start_time
        valid_count = len([r for r in all_results if r.get('is_valid', False)])
        invalid_count = total_emails - valid_count
        
        stats = {
            "total_emails": total_emails,
            "valid_emails": valid_count,
            "invalid_emails": invalid_count,
            "success_rate": f"{(valid_count/total_emails*100):.1f}%",
            "processing_time": f"{total_time:.2f}s",
            "avg_time_per_email": f"{total_time/total_emails:.3f}s",
            "format_errors": len([r for r in all_results if not r.get('format_valid', True)]),
            "domain_errors": len([r for r in all_results if not r.get('domain_exists', True)]),
            "mx_errors": len([r for r in all_results if not r.get('mx_record_exists', True)]),
            "disposable_emails": len([r for r in all_results if 'desechable' in str(r.get('warnings', []))])
        }
        
        # Guardar resultados
        if output_file:
            self.save_results(all_results, stats, output_file)
        
        return {
            "results": all_results,
            "stats": stats
        }
    
    def save_results(self, results: List[Dict], stats: Dict, output_file: str):
        """Guarda los resultados en diferentes formatos"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Guardar CSV detallado
        csv_file = f"{output_file}_detailed_{timestamp}.csv"
        df_results = pd.DataFrame(results)
        df_results.to_csv(csv_file, index=False)
        print(f"💾 Resultados detallados guardados en: {csv_file}")
        
        # Guardar CSV resumido (solo emails válidos/inválidos)
        summary_file = f"{output_file}_summary_{timestamp}.csv"
        df_summary = pd.DataFrame([
            {
                "email": r["email"],
                "is_valid": r["is_valid"],
                "errors": "; ".join(r.get("errors", [])),
                "warnings": "; ".join(r.get("warnings", [])),
                "validation_time": r.get("validation_time", 0)
            }
            for r in results
        ])
        df_summary.to_csv(summary_file, index=False)
        print(f"📋 Resumen guardado en: {summary_file}")
        
        # Guardar estadísticas JSON
        stats_file = f"{output_file}_stats_{timestamp}.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        print(f"📊 Estadísticas guardadas en: {stats_file}")
        
        # Mostrar estadísticas
        print("\n" + "="*50)
        print("📊 ESTADÍSTICAS FINALES")
        print("="*50)
        for key, value in stats.items():
            print(f"{key.replace('_', ' ').title()}: {value}")
        print("="*50)

def main():
    parser = argparse.ArgumentParser(description="Validar emails desde un archivo CSV")
    parser.add_argument("csv_file", help="Archivo CSV con emails")
    parser.add_argument("-c", "--column", help="Nombre de la columna con emails")
    parser.add_argument("-o", "--output", default="email_validation_results", 
                       help="Prefijo para archivos de salida")
    parser.add_argument("-b", "--batch-size", type=int, default=50,
                       help="Tamaño del lote para procesamiento")
    parser.add_argument("--no-domain", action="store_true",
                       help="No verificar existencia del dominio")
    parser.add_argument("--no-mx", action="store_true",
                       help="No verificar registros MX")
    parser.add_argument("--check-smtp", action="store_true",
                       help="Verificar conexión SMTP (lento)")
    parser.add_argument("--api-url", default="http://localhost:8000",
                       help="URL base de la API")
    
    args = parser.parse_args()
    
    # Verificar que el archivo existe
    import os
    if not os.path.exists(args.csv_file):
        print(f"❌ Archivo no encontrado: {args.csv_file}")
        sys.exit(1)
    
    # Crear validador
    validator = CSVEmailValidator(args.api_url)
    
    # Procesar CSV
    result = validator.process_csv(
        csv_file=args.csv_file,
        output_file=args.output,
        email_column=args.column,
        batch_size=args.batch_size,
        check_domain=not args.no_domain,
        check_mx=not args.no_mx,
        check_smtp=args.check_smtp
    )
    
    if "error" in result:
        print(f"❌ Error: {result['error']}")
        sys.exit(1)
    
    print("\n✅ Validación completada exitosamente!")

if __name__ == "__main__":
    main() 