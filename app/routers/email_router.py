from fastapi import APIRouter, HTTPException, Query, BackgroundTasks, UploadFile, File
from fastapi.responses import JSONResponse
from app.models.email_models import (
    EmailRequest, 
    EmailValidationResult, 
    BatchEmailRequest, 
    BatchEmailResult,
    DomainInfo,
    ErrorResponse
)
from app.services.email_service import EmailValidationService
from app.config.settings import settings
import time
import logging
import pandas as pd
import io
from typing import Optional

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/email", tags=["email-validation"])

@router.post("/validate", response_model=EmailValidationResult)
async def validate_email(request: EmailRequest):
    """
    Valida un correo electrónico con diferentes niveles de verificación.
    
    - **email**: Dirección de correo electrónico a validar
    - **check_domain**: Verificar si el dominio existe
    - **check_mx**: Verificar registros MX del dominio
    - **check_smtp**: Verificar conexión SMTP (más lento)
    """
    try:
        result = EmailValidationService.validate_email(request)
        return result
    except Exception as e:
        logger.error(f"Error validando email {request.email}: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Error interno al validar el email: {str(e)}"
        )

@router.post("/validate-batch", response_model=BatchEmailResult)
async def validate_emails_batch(request: BatchEmailRequest):
    """
    Valida múltiples correos electrónicos en lote.
    
    - **emails**: Lista de correos electrónicos (máximo 100)
    - **check_domain**: Verificar si los dominios existen
    - **check_mx**: Verificar registros MX de los dominios
    - **check_smtp**: Verificar conexión SMTP (no recomendado para lotes grandes)
    """
    try:
        start_time = time.time()
        results = []
        
        # Validar límite de lote
        if len(request.emails) > settings.MAX_BATCH_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"Máximo {settings.MAX_BATCH_SIZE} emails por lote"
            )
        
        # Procesar cada email
        for email in request.emails:
            try:
                email_request = EmailRequest(
                    email=email,
                    check_domain=request.check_domain,
                    check_mx=request.check_mx,
                    check_smtp=request.check_smtp
                )
                result = EmailValidationService.validate_email(email_request)
                results.append(result)
            except Exception as e:
                logger.error(f"Error procesando email {email}: {e}")
                # Crear resultado de error para este email
                error_result = EmailValidationResult(
                    email=email,
                    is_valid=False,
                    format_valid=False,
                    domain_exists=False,
                    mx_record_exists=False,
                    errors=[f"Error procesando email: {str(e)}"]
                )
                results.append(error_result)
        
        processing_time = time.time() - start_time
        valid_count = len([r for r in results if r.is_valid])
        invalid_count = len(results) - valid_count
        
        # Crear resumen
        summary = {
            "success_rate": f"{(valid_count/len(results)*100):.1f}%",
            "avg_processing_time": f"{processing_time/len(results):.3f}s",
            "disposable_emails": len([r for r in results if "desechable" in str(r.warnings)]),
            "format_errors": len([r for r in results if not r.format_valid]),
            "domain_errors": len([r for r in results if not r.domain_exists]),
            "mx_errors": len([r for r in results if not r.mx_record_exists])
        }
        
        return BatchEmailResult(
            total=len(results),
            valid=valid_count,
            invalid=invalid_count,
            processing_time=processing_time,
            results=results,
            summary=summary
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en validación por lotes: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error interno en validación por lotes: {str(e)}"
        )

@router.get("/validate-simple/{email}")
async def validate_simple_email(email: str):
    """
    Validación simple basada únicamente en el formato del email.
    
    - **email**: Dirección de correo electrónico a validar
    """
    try:
        is_valid = EmailValidationService.validate_email_format(email)
        is_disposable = EmailValidationService.is_disposable_email(email)
        
        return {
            "email": email,
            "is_valid": is_valid,
            "is_disposable": is_disposable,
            "validation_type": "format_only"
        }
    except Exception as e:
        logger.error(f"Error en validación simple de {email}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error al validar el formato del email: {str(e)}"
        )

@router.get("/validate-deep/{email}")
async def validate_deep_email(email: str):
    """
    Validación profunda que incluye verificación de existencia real y bandeja llena.
    
    - **email**: Dirección de correo electrónico a validar
    - Incluye verificación SMTP avanzada
    - Detecta si el buzón está lleno
    - Verifica si el email realmente existe
    """
    try:
        # Crear request con todas las validaciones habilitadas
        request = EmailRequest(
            email=email,
            check_domain=True,
            check_mx=True,
            check_smtp=True
        )
        
        result = EmailValidationService.validate_email(request)
        
        # Agregar información adicional para validación profunda
        response = {
            "email": result.email,
            "is_valid": result.is_valid,
            "format_valid": result.format_valid,
            "domain_exists": result.domain_exists,
            "mx_record_exists": result.mx_record_exists,
            "smtp_valid": result.smtp_valid,
            "validation_time": result.validation_time,
            "errors": result.errors,
            "warnings": result.warnings,
            "validation_type": "deep_smtp"
        }
        
        # Agregar detalles SMTP si están disponibles
        if result.smtp_details:
            response["smtp_details"] = {
                "email_exists": result.smtp_details.exists,
                "deliverable": result.smtp_details.deliverable,
                "mailbox_full": result.smtp_details.mailbox_full,
                "catch_all": result.smtp_details.catch_all,
                "smtp_code": result.smtp_details.smtp_code,
                "smtp_message": result.smtp_details.smtp_message,
                "details": result.smtp_details.details
            }
        
        # Agregar información del dominio si está disponible
        if result.domain_info:
            response["domain_info"] = result.domain_info
        
        return response
        
    except Exception as e:
        logger.error(f"Error en validación profunda de {email}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error al validar el email: {str(e)}"
        )

@router.get("/validate-ultra/{email}")
async def validate_ultra_email(email: str):
    """
    Validación ULTRA-PROFUNDA que NUNCA falla - El scan más completo posible.
    
    - **email**: Dirección de correo electrónico a validar
    - Análisis de formato avanzado con sugerencias
    - Verificación DNS multi-servidor con IPv4/IPv6
    - Análisis MX completo con prioridades
    - Validación SMTP ultra-robusta con múltiples intentos
    - Detección de seguridad y patrones sospechosos
    - Puntuación de confianza de 0-100
    - Recomendaciones inteligentes
    - Nunca falla, siempre retorna un resultado
    """
    try:
        result = EmailValidationService.validate_email_ultra_deep(email)
        return result
        
    except Exception as e:
        # Incluso si hay un error crítico, retornamos un resultado básico
        logger.error(f"Error crítico en validación ultra-profunda de {email}: {e}")
        return {
            "email": email if email else "",
            "is_valid": False,
            "confidence_score": 0,
            "validation_level": "ultra_deep_error",
            "format_analysis": {},
            "domain_analysis": {},
            "mx_analysis": {},
            "smtp_analysis": {},
            "security_analysis": {},
            "recommendations": ["Error crítico en validación, email no recomendado"],
            "errors": [f"Error crítico: {str(e)}"],
            "warnings": [],
            "processing_time": 0
        }

@router.get("/domain-info/{domain}", response_model=DomainInfo)
async def get_domain_info(domain: str):
    """
    Obtiene información detallada sobre un dominio.
    
    - **domain**: Nombre del dominio a consultar
    """
    try:
        domain_info = EmailValidationService.get_domain_info(domain)
        return domain_info
    except Exception as e:
        logger.error(f"Error obteniendo info del dominio {domain}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener información del dominio: {str(e)}"
        )

@router.get("/validator-info")
async def get_validator_info():
    """
    Obtiene información sobre el validador y su IP.
    
    - Retorna la IP pública del validador
    - Estado de reputación conocido
    - Recomendaciones para mejorar la validación
    """
    try:
        import requests
        import socket
        
        # Obtener IP pública
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            public_ip = response.json().get('ip', 'No disponible')
        except:
            public_ip = 'No disponible'
        
        # Obtener IP local
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except:
            local_ip = 'No disponible'
        
        # Información del validador
        validator_info = {
            "validator_status": "✅ Operativo",
            "public_ip": public_ip,
            "local_ip": local_ip,
            "dns_servers": ["8.8.8.8", "1.1.1.1", "208.67.222.222"],
            "smtp_timeout": settings.SMTP_TIMEOUT,
            "dns_timeout": settings.DNS_TIMEOUT,
            "reputation_notes": [
                "Si experimentas bloqueos SMTP frecuentes:",
                "1. Tu IP puede estar en listas negras (RBL)",
                "2. Algunos servidores bloquean IPs residenciales",
                "3. Considera usar un servidor VPS/dedicado",
                "4. Verifica en: https://www.spamhaus.org/lookup/"
            ],
            "optimization_tips": [
                "🔧 Usa IP con buena reputación para SMTP",
                "🌐 Considera proxy/VPN empresarial",
                "⚡ Configura rate limiting apropiado",
                "🛡️ Implementa rotación de IPs si es necesario"
            ]
        }
        
        return validator_info
        
    except Exception as e:
        logger.error(f"Error obteniendo información del validador: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener información del validador: {str(e)}"
        )

@router.get("/stats")
async def get_validation_stats():
    """
    Obtiene estadísticas del servicio de validación.
    """
    return {
        "service": "Email Validation API",
        "version": settings.APP_VERSION,
        "max_batch_size": settings.MAX_BATCH_SIZE,
        "smtp_timeout": settings.SMTP_TIMEOUT,
        "dns_timeout": settings.DNS_TIMEOUT,
        "disposable_domains_count": len(EmailValidationService.DISPOSABLE_DOMAINS)
    }

@router.get("/health")
async def health_check():
    """
    Verificación de salud del servicio de validación de emails.
    """
    try:
        # Hacer una validación simple para verificar que el servicio funciona
        test_result = EmailValidationService.validate_email_format("test@example.com")
        
        return {
            "status": "healthy",
            "service": "email-validation",
            "test_validation": test_result,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception as e:
        logger.error(f"Error en health check: {e}")
        raise HTTPException(
            status_code=503,
            detail="Servicio de validación no disponible"
        )

@router.post("/validate-csv")
async def validate_csv_file(
    file: UploadFile = File(...),
    email_column: Optional[str] = Query(None, description="Nombre de la columna con emails"),
    validation_level: str = Query("ultra_deep", description="Nivel de validación: 'standard', 'deep', 'ultra_deep'"),
    batch_size: int = Query(25, description="Tamaño del lote para procesamiento", ge=1, le=50),
    include_details: bool = Query(True, description="Incluir análisis detallado en resultados"),
    export_format: str = Query("json", description="Formato de exportación: 'json', 'csv'"),
    confidence_threshold: int = Query(60, description="Umbral mínimo de confianza (0-100)", ge=0, le=100)
):
    """
    🚀 VALIDACIÓN CSV ULTRA-ROBUSTA - El procesador más avanzado de emails en CSV
    
    - **file**: Archivo CSV con emails (UTF-8, Latin-1, múltiples encodings soportados)
    - **email_column**: Nombre de la columna con emails (detección automática inteligente)
    - **validation_level**: Nivel de validación ('standard', 'deep', 'ultra_deep')
    - **batch_size**: Tamaño del lote (1-50, optimizado para rendimiento)
    - **include_details**: Incluir análisis completo en resultados
    - **export_format**: Formato de salida ('json', 'csv')
    - **confidence_threshold**: Umbral mínimo de confianza para marcar como válido
    
    🎯 CARACTERÍSTICAS ULTRA-ROBUSTAS:
    - ✅ Nunca falla, siempre retorna resultado
    - 🔍 Detección automática de columnas de email
    - 🌐 Soporte para múltiples encodings
    - 📊 Análisis estadístico avanzado
    - 🛡️ Manejo robusto de errores
    - ⚡ Procesamiento optimizado en lotes
    - 🎯 Puntuación de confianza inteligente
    """
    
    # Variables para tracking robusto
    start_time = time.time()
    processing_stats = {
        "total_processed": 0,
        "successful_validations": 0,
        "failed_validations": 0,
        "high_confidence": 0,
        "medium_confidence": 0,
        "low_confidence": 0,
        "ip_reputation_issues": 0,
        "disposable_emails": 0,
        "format_errors": 0,
        "domain_errors": 0,
        "mx_errors": 0,
        "smtp_errors": 0
    }
    
    try:
        # 1. VALIDACIÓN ROBUSTA DEL ARCHIVO
        logger.info(f"🔍 Iniciando validación CSV ultra-robusta: {file.filename}")
        
        # Verificar extensión del archivo
        if not file.filename or not any(file.filename.lower().endswith(ext) for ext in ['.csv', '.txt']):
            raise HTTPException(
                status_code=400,
                detail="❌ El archivo debe ser CSV (.csv) o texto (.txt)"
            )
        
        # Verificar tamaño del archivo (máximo 10MB)
        file_size = 0
        content = await file.read()
        file_size = len(content)
        
        if file_size > 10 * 1024 * 1024:  # 10MB
            raise HTTPException(
                status_code=400,
                detail="❌ El archivo excede el tamaño máximo de 10MB"
            )
        
        if file_size == 0:
            raise HTTPException(
                status_code=400,
                detail="❌ El archivo está vacío"
            )
        
        logger.info(f"📁 Archivo válido: {file.filename} ({file_size:,} bytes)")
        
        # 2. LECTURA ULTRA-ROBUSTA CON MÚLTIPLES ENCODINGS
        df = None
        encoding_used = None
        
        # Lista de encodings a probar en orden de preferencia
        encodings_to_try = [
            'utf-8',
            'utf-8-sig',  # UTF-8 con BOM
            'latin-1',
            'iso-8859-1',
            'cp1252',     # Windows-1252
            'ascii'
        ]
        
        # Lista de separadores a probar
        separators_to_try = [',', ';', '\t', '|']
        
        for encoding in encodings_to_try:
            try:
                decoded_content = content.decode(encoding)
                
                # Probar diferentes separadores
                for separator in separators_to_try:
                    try:
                        df_test = pd.read_csv(io.StringIO(decoded_content), sep=separator)
                        
                        # Verificar que tiene al menos 2 columnas y 1 fila
                        if len(df_test.columns) >= 1 and len(df_test) > 0:
                            df = df_test
                            encoding_used = encoding
                            logger.info(f"✅ Archivo leído exitosamente: encoding={encoding}, separador='{separator}'")
                            break
                    except Exception as e:
                        continue
                
                if df is not None:
                    break
                    
            except UnicodeDecodeError:
                continue
        
        if df is None:
            raise HTTPException(
                status_code=400,
                detail="❌ No se pudo leer el archivo CSV. Verifica el formato y la codificación."
            )
        
        # 3. DETECCIÓN INTELIGENTE DE COLUMNA DE EMAIL
        email_column_detected = None
        
        if email_column is None:
            # Patrones para detectar columnas de email
            email_patterns = [
                'email', 'correo', 'mail', 'e-mail', 'e_mail',
                'address', 'direccion', 'contact', 'contacto',
                'usuario', 'user', 'account', 'cuenta'
            ]
            
            # Buscar por nombre de columna
            for col in df.columns:
                col_lower = str(col).lower().strip()
                if any(pattern in col_lower for pattern in email_patterns):
                    email_column_detected = col
                    break
            
            # Si no se encontró por nombre, buscar por contenido
            if email_column_detected is None:
                for col in df.columns:
                    try:
                        sample_values = df[col].dropna().astype(str).head(10).tolist()
                        email_count = sum(1 for val in sample_values if '@' in val and '.' in val)
                        
                        # Si más del 50% de la muestra parece email
                        if email_count > len(sample_values) * 0.5:
                            email_column_detected = col
                            break
                    except:
                        continue
            
            if email_column_detected is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"❌ No se pudo detectar columna de email automáticamente. "
                           f"Columnas disponibles: {', '.join(df.columns)}. "
                           f"Especifica 'email_column' manualmente."
                )
            
            email_column = email_column_detected
            logger.info(f"🎯 Columna de email detectada automáticamente: '{email_column}'")
        
        # Validar que la columna especificada existe
        if email_column not in df.columns:
            raise HTTPException(
                status_code=400,
                detail=f"❌ Columna '{email_column}' no encontrada. "
                       f"Columnas disponibles: {', '.join(df.columns)}"
            )
        
        # 4. EXTRACCIÓN Y LIMPIEZA INTELIGENTE DE EMAILS
        logger.info(f"🧹 Extrayendo y limpiando emails de la columna '{email_column}'")
        
        # Extraer emails con limpieza avanzada
        raw_emails = df[email_column].dropna().astype(str).tolist()
        
        # Limpiar y filtrar emails
        cleaned_emails = []
        for email in raw_emails:
            # Limpiar espacios, comillas, etc.
            cleaned = email.strip().strip('"').strip("'").lower()
            
            # Filtrar valores obviamente no válidos
            if (cleaned and 
                cleaned not in ['nan', 'null', 'none', '', 'n/a', 'na'] and
                '@' in cleaned and
                len(cleaned) > 5):
                cleaned_emails.append(cleaned)
        
        # Remover duplicados manteniendo orden
        unique_emails = []
        seen = set()
        for email in cleaned_emails:
            if email not in seen:
                unique_emails.append(email)
                seen.add(email)
        
        if not unique_emails:
            raise HTTPException(
                status_code=400,
                detail="❌ No se encontraron emails válidos en el archivo"
            )
        
        total_emails = len(unique_emails)
        logger.info(f"📧 Emails procesables encontrados: {total_emails} (únicos: {len(unique_emails)})")
        
        # 5. PROCESAMIENTO ULTRA-ROBUSTO EN LOTES
        logger.info(f"🚀 Iniciando procesamiento {validation_level} en lotes de {batch_size}")
        
        all_results = []
        processing_stats["total_processed"] = total_emails
        
        for i in range(0, total_emails, batch_size):
            batch = unique_emails[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (total_emails + batch_size - 1) // batch_size
            
            logger.info(f"📦 Procesando lote {batch_num}/{total_batches} ({len(batch)} emails)")
            
            # Procesar cada email del lote con máxima robustez
            batch_results = []
            for email in batch:
                try:
                    # Seleccionar método de validación según el nivel
                    if validation_level == "ultra_deep":
                        result = EmailValidationService.validate_email_ultra_deep(email)
                        
                        # Convertir resultado ultra-profundo a formato estándar
                        email_result = {
                            "email": result["email"],
                            "is_valid": result["is_valid"],
                            "confidence_score": result["confidence_score"],
                            "validation_level": result["validation_level"],
                            "processing_time": result["processing_time"],
                            "errors": result["errors"],
                            "warnings": result["warnings"],
                            "recommendations": result["recommendations"]
                        }
                        
                        # Agregar detalles si se solicita
                        if include_details:
                            email_result.update({
                                "format_analysis": result["format_analysis"],
                                "domain_analysis": result["domain_analysis"],
                                "mx_analysis": result["mx_analysis"],
                                "smtp_analysis": result["smtp_analysis"],
                                "security_analysis": result["security_analysis"]
                            })
                        
                        # Actualizar estadísticas
                        if result["confidence_score"] >= 80:
                            processing_stats["high_confidence"] += 1
                        elif result["confidence_score"] >= 60:
                            processing_stats["medium_confidence"] += 1
                        else:
                            processing_stats["low_confidence"] += 1
                        
                        # Detectar problemas específicos
                        if any(attempt.get("ip_reputation_issue", False) for attempt in result.get("smtp_analysis", {}).get("attempts", [])):
                            processing_stats["ip_reputation_issues"] += 1
                        
                        if result.get("security_analysis", {}).get("is_disposable", False):
                            processing_stats["disposable_emails"] += 1
                        
                        if not result.get("format_analysis", {}).get("is_valid", True):
                            processing_stats["format_errors"] += 1
                        
                        if not result.get("domain_analysis", {}).get("exists", True):
                            processing_stats["domain_errors"] += 1
                        
                        if not result.get("mx_analysis", {}).get("has_mx", True):
                            processing_stats["mx_errors"] += 1
                        
                        # Marcar como válido según umbral de confianza
                        email_result["is_valid"] = result["confidence_score"] >= confidence_threshold
                        
                    elif validation_level == "deep":
                        # Validación profunda estándar
                        email_request = EmailRequest(
                            email=email,
                            check_domain=True,
                            check_mx=True,
                            check_smtp=True
                        )
                        result = EmailValidationService.validate_email(email_request)
                        
                        email_result = {
                            "email": result.email,
                            "is_valid": result.is_valid,
                            "confidence_score": 75 if result.is_valid else 25,  # Estimación
                            "validation_level": "deep",
                            "format_valid": result.format_valid,
                            "domain_exists": result.domain_exists,
                            "mx_record_exists": result.mx_record_exists,
                            "smtp_valid": result.smtp_valid,
                            "processing_time": result.validation_time,
                            "errors": result.errors,
                            "warnings": result.warnings
                        }
                        
                        if include_details and result.smtp_details:
                            email_result["smtp_details"] = {
                                "exists": result.smtp_details.exists,
                                "deliverable": result.smtp_details.deliverable,
                                "mailbox_full": result.smtp_details.mailbox_full,
                                "catch_all": result.smtp_details.catch_all,
                                "smtp_code": result.smtp_details.smtp_code,
                                "smtp_message": result.smtp_details.smtp_message
                            }
                    
                    else:  # standard
                        # Validación estándar rápida
                        email_request = EmailRequest(
                            email=email,
                            check_domain=True,
                            check_mx=True,
                            check_smtp=False
                        )
                        result = EmailValidationService.validate_email(email_request)
                        
                        email_result = {
                            "email": result.email,
                            "is_valid": result.is_valid,
                            "confidence_score": 60 if result.is_valid else 20,  # Estimación
                            "validation_level": "standard",
                            "format_valid": result.format_valid,
                            "domain_exists": result.domain_exists,
                            "mx_record_exists": result.mx_record_exists,
                            "processing_time": result.validation_time,
                            "errors": result.errors,
                            "warnings": result.warnings
                        }
                    
                    batch_results.append(email_result)
                    processing_stats["successful_validations"] += 1
                    
                except Exception as e:
                    logger.error(f"❌ Error procesando email {email}: {e}")
                    
                    # Crear resultado de error ultra-robusto
                    error_result = {
                        "email": email,
                        "is_valid": False,
                        "confidence_score": 0,
                        "validation_level": validation_level,
                        "processing_time": 0,
                        "errors": [f"Error crítico: {str(e)}"],
                        "warnings": ["Email no procesado debido a error interno"],
                        "recommendations": ["❌ Email no recomendado - Error en procesamiento"]
                    }
                    
                    batch_results.append(error_result)
                    processing_stats["failed_validations"] += 1
            
            all_results.extend(batch_results)
            
            # Log de progreso
            progress = (i + len(batch)) / total_emails * 100
            logger.info(f"📊 Progreso: {progress:.1f}% ({i + len(batch)}/{total_emails})")
        
        # 6. ANÁLISIS ESTADÍSTICO AVANZADO
        total_processing_time = time.time() - start_time
        
        # Calcular estadísticas finales
        valid_results = [r for r in all_results if r.get("is_valid", False)]
        invalid_results = [r for r in all_results if not r.get("is_valid", False)]
        
        confidence_scores = [r.get("confidence_score", 0) for r in all_results]
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        # Análisis de calidad del dataset
        quality_analysis = {
            "dataset_quality": "Alta" if avg_confidence >= 70 else "Media" if avg_confidence >= 50 else "Baja",
            "avg_confidence_score": round(avg_confidence, 1),
            "confidence_distribution": {
                "high_confidence": processing_stats["high_confidence"],
                "medium_confidence": processing_stats["medium_confidence"],
                "low_confidence": processing_stats["low_confidence"]
            },
            "common_issues": []
        }
        
        # Identificar problemas comunes
        if processing_stats["ip_reputation_issues"] > total_emails * 0.3:
            quality_analysis["common_issues"].append("🚫 Múltiples bloqueos por reputación de IP del validador")
        
        if processing_stats["disposable_emails"] > total_emails * 0.2:
            quality_analysis["common_issues"].append("🗑️ Alto porcentaje de emails desechables")
        
        if processing_stats["format_errors"] > total_emails * 0.1:
            quality_analysis["common_issues"].append("📝 Múltiples errores de formato")
        
        if processing_stats["domain_errors"] > total_emails * 0.15:
            quality_analysis["common_issues"].append("🌐 Múltiples dominios inexistentes")
        
        # 7. RESUMEN ULTRA-DETALLADO
        summary = {
            "🎯 Resumen General": {
                "archivo_procesado": file.filename,
                "encoding_detectado": encoding_used,
                "columna_email": email_column,
                "nivel_validacion": validation_level,
                "umbral_confianza": confidence_threshold
            },
            "📊 Estadísticas de Procesamiento": {
                "total_emails": total_emails,
                "emails_validos": len(valid_results),
                "emails_invalidos": len(invalid_results),
                "tasa_exito": f"{(len(valid_results)/total_emails*100):.1f}%",
                "tiempo_total": f"{total_processing_time:.2f}s",
                "tiempo_promedio": f"{total_processing_time/total_emails:.3f}s/email"
            },
            "🎯 Análisis de Confianza": quality_analysis,
            "🔍 Problemas Detectados": {
                "errores_formato": processing_stats["format_errors"],
                "errores_dominio": processing_stats["domain_errors"],
                "errores_mx": processing_stats["mx_errors"],
                "emails_desechables": processing_stats["disposable_emails"],
                "problemas_reputacion_ip": processing_stats["ip_reputation_issues"]
            },
            "💡 Recomendaciones": []
        }
        
        # Generar recomendaciones inteligentes
        if processing_stats["ip_reputation_issues"] > 0:
            summary["💡 Recomendaciones"].append(
                f"🌐 {processing_stats['ip_reputation_issues']} emails tuvieron problemas de reputación de IP. "
                "Considera usar el validador desde una IP con mejor reputación."
            )
        
        if processing_stats["disposable_emails"] > 0:
            summary["💡 Recomendaciones"].append(
                f"🗑️ {processing_stats['disposable_emails']} emails desechables detectados. "
                "Considera filtrarlos según tu política de emails."
            )
        
        if avg_confidence < 60:
            summary["💡 Recomendaciones"].append(
                "⚠️ Confianza promedio baja. Considera limpiar el dataset o usar validación manual adicional."
            )
        
        if len(valid_results) > 0:
            summary["💡 Recomendaciones"].append(
                f"✅ {len(valid_results)} emails válidos listos para usar en campañas de marketing."
            )
        
        # 8. RESPUESTA ULTRA-COMPLETA
        response = {
            "🎉 status": "success",
            "message": f"✅ Procesamiento ultra-robusto completado: {file.filename}",
            "summary": summary,
            "processing_stats": processing_stats,
            "results": all_results if export_format == "json" else f"Procesados {total_emails} emails",
            "metadata": {
                "validation_level": validation_level,
                "include_details": include_details,
                "export_format": export_format,
                "confidence_threshold": confidence_threshold,
                "batch_size": batch_size,
                "total_processing_time": total_processing_time,
                "api_version": "ultra_robust_v2.0"
            }
        }
        
        logger.info(f"✅ Procesamiento completado exitosamente: {total_emails} emails en {total_processing_time:.2f}s")
        return response
        
    except HTTPException:
        # Re-raise HTTP exceptions (errores de validación)
        raise
    
    except Exception as e:
        # Manejo ultra-robusto de errores críticos
        logger.error(f"💥 Error crítico en validación CSV: {e}")
        
        # Incluso en caso de error crítico, intentar retornar información útil
        error_response = {
            "🚨 status": "error",
            "message": "❌ Error crítico en procesamiento, pero el sistema no falló completamente",
            "error_details": str(e),
            "processing_stats": processing_stats,
            "partial_results": all_results if 'all_results' in locals() else [],
            "recommendations": [
                "🔧 Verifica el formato del archivo CSV",
                "📧 Asegúrate de que hay una columna con emails válidos",
                "🌐 Intenta con un archivo más pequeño para testing",
                "💡 Contacta soporte si el problema persiste"
            ],
            "metadata": {
                "validation_level": validation_level,
                "file_size": file_size if 'file_size' in locals() else 0,
                "encoding_used": encoding_used if 'encoding_used' in locals() else None,
                "api_version": "ultra_robust_v2.0"
            }
        }
        
        # Retornar error 500 pero con información útil
        raise HTTPException(
            status_code=500,
            detail=error_response
        )