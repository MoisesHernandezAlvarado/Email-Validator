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
    check_domain: bool = Query(True, description="Verificar si el dominio existe"),
    check_mx: bool = Query(True, description="Verificar registros MX del dominio"),
    check_smtp: bool = Query(False, description="Verificar conexión SMTP (lento)"),
    batch_size: int = Query(50, description="Tamaño del lote para procesamiento", ge=1, le=100)
):
    """
    Valida emails desde un archivo CSV subido.
    
    - **file**: Archivo CSV con emails
    - **email_column**: Nombre de la columna con emails (opcional, se detecta automáticamente)
    - **check_domain**: Verificar si el dominio existe
    - **check_mx**: Verificar registros MX del dominio
    - **check_smtp**: Verificar conexión SMTP (más lento)
    - **batch_size**: Tamaño del lote para procesamiento (1-100)
    """
    try:
        # Verificar que es un archivo CSV
        if not file.filename.endswith('.csv'):
            raise HTTPException(
                status_code=400,
                detail="El archivo debe ser un CSV (.csv)"
            )
        
        # Leer el contenido del archivo
        content = await file.read()
        
        # Convertir a DataFrame
        try:
            df = pd.read_csv(io.StringIO(content.decode('utf-8')))
        except UnicodeDecodeError:
            # Intentar con diferentes encodings
            try:
                df = pd.read_csv(io.StringIO(content.decode('latin-1')))
            except:
                raise HTTPException(
                    status_code=400,
                    detail="Error al leer el archivo CSV. Verifica la codificación."
                )
        
        if df.empty:
            raise HTTPException(
                status_code=400,
                detail="El archivo CSV está vacío"
            )
        
        # Detectar columna de email automáticamente si no se especifica
        if email_column is None:
            email_cols = [col for col in df.columns if any(
                keyword in col.lower() for keyword in ['email', 'correo', 'mail']
            )]
            
            if email_cols:
                email_column = email_cols[0]
                logger.info(f"Columna de email detectada automáticamente: {email_column}")
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"No se encontró columna de email. Columnas disponibles: {', '.join(df.columns)}"
                )
        
        # Validar que la columna existe
        if email_column not in df.columns:
            raise HTTPException(
                status_code=400,
                detail=f"Columna '{email_column}' no encontrada. Columnas disponibles: {', '.join(df.columns)}"
            )
        
        # Extraer y limpiar emails
        emails = df[email_column].dropna().astype(str).tolist()
        emails = [email.strip() for email in emails if email.strip()]
        
        if not emails:
            raise HTTPException(
                status_code=400,
                detail="No se encontraron emails válidos en el archivo"
            )
        
        logger.info(f"Procesando {len(emails)} emails desde CSV: {file.filename}")
        
        # Procesar en lotes
        start_time = time.time()
        all_results = []
        total_emails = len(emails)
        
        for i in range(0, total_emails, batch_size):
            batch = emails[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (total_emails + batch_size - 1) // batch_size
            
            logger.info(f"Procesando lote {batch_num}/{total_batches} ({len(batch)} emails)")
            
            # Procesar cada email del lote
            batch_results = []
            for email in batch:
                try:
                    email_request = EmailRequest(
                        email=email,
                        check_domain=check_domain,
                        check_mx=check_mx,
                        check_smtp=check_smtp
                    )
                    result = EmailValidationService.validate_email(email_request)
                    batch_results.append(result)
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
                    batch_results.append(error_result)
            
            all_results.extend(batch_results)
        
        # Calcular estadísticas
        processing_time = time.time() - start_time
        valid_count = len([r for r in all_results if r.is_valid])
        invalid_count = total_emails - valid_count
        
        # Crear resumen detallado
        summary = {
            "success_rate": f"{(valid_count/total_emails*100):.1f}%",
            "avg_processing_time": f"{processing_time/total_emails:.3f}s",
            "disposable_emails": len([r for r in all_results if "desechable" in str(r.warnings)]),
            "format_errors": len([r for r in all_results if not r.format_valid]),
            "domain_errors": len([r for r in all_results if not r.domain_exists]),
            "mx_errors": len([r for r in all_results if not r.mx_record_exists]),
            "file_info": {
                "filename": file.filename,
                "email_column": email_column,
                "total_rows": len(df),
                "processed_emails": total_emails
            }
        }
        
        return {
            "message": f"Procesamiento completado para {file.filename}",
            "total": total_emails,
            "valid": valid_count,
            "invalid": invalid_count,
            "processing_time": processing_time,
            "results": all_results,
            "summary": summary
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error procesando archivo CSV: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error interno procesando el archivo CSV: {str(e)}"
        )