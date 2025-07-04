import re
import dns.resolver
import socket
import smtplib
import time
from typing import List, Optional
from app.models.email_models import EmailValidationResult, EmailRequest, DomainInfo
from app.config.settings import settings
import logging

logger = logging.getLogger(__name__)

class EmailValidationService:
    
    # Patrones comunes de dominios temporales/desechables
    DISPOSABLE_DOMAINS = {
        '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
        'mailinator.com', 'throwaway.email', 'temp-mail.org'
    }
    
    @staticmethod
    def validate_email_format(email: str) -> bool:
        """Valida el formato del correo usando regex mejorado"""
        # Patrón más estricto para validación de emails
        pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(pattern, email):
            return False
        
        # Verificaciones adicionales
        local_part, domain = email.split('@')
        
        # Verificar longitud
        if len(local_part) > 64 or len(domain) > 253:
            return False
        
        # Verificar que no empiece o termine con punto
        if local_part.startswith('.') or local_part.endswith('.'):
            return False
        
        # Verificar puntos consecutivos
        if '..' in local_part or '..' in domain:
            return False
        
        return True

    @staticmethod
    def validate_domain_exists(domain: str) -> tuple[bool, List[str]]:
        """Verifica si el dominio existe y obtiene registros A"""
        try:
            # Crear un resolver personalizado con timeout
            resolver = dns.resolver.Resolver()
            resolver.timeout = settings.DNS_TIMEOUT
            resolver.lifetime = settings.DNS_TIMEOUT
            
            # Obtener registros A
            answers = resolver.resolve(domain, 'A')
            a_records = [str(answer) for answer in answers]
            return True, a_records
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Dominio no existe: {domain}")
            return False, []
        except dns.resolver.NoAnswer:
            logger.warning(f"No hay respuesta para el dominio: {domain}")
            return False, []
        except Exception as e:
            logger.error(f"Error verificando dominio {domain}: {e}")
            return False, []

    @staticmethod
    def validate_mx_record(domain: str) -> tuple[bool, List[str]]:
        """Verifica si el dominio tiene registros MX"""
        try:
            # Crear un resolver personalizado con timeout
            resolver = dns.resolver.Resolver()
            resolver.timeout = settings.DNS_TIMEOUT
            resolver.lifetime = settings.DNS_TIMEOUT
            
            mx_records = resolver.resolve(domain, 'MX')
            mx_list = [str(record.exchange) for record in mx_records]
            return True, mx_list
        except dns.resolver.NXDOMAIN:
            logger.warning(f"No se encontraron registros MX para: {domain}")
            return False, []
        except dns.resolver.NoAnswer:
            logger.warning(f"No hay respuesta MX para el dominio: {domain}")
            return False, []
        except Exception as e:
            logger.error(f"Error verificando MX para {domain}: {e}")
            return False, []

    @staticmethod
    def validate_smtp_connection(email: str) -> dict:
        """Valida la conexión SMTP avanzada con detalles de existencia y bandeja llena"""
        result = {
            "exists": False,
            "deliverable": False,
            "mailbox_full": False,
            "catch_all": False,
            "smtp_code": None,
            "smtp_message": "",
            "details": []
        }
        
        try:
            domain = email.split('@')[1]
            
            # Crear un resolver personalizado con timeout
            resolver = dns.resolver.Resolver()
            resolver.timeout = settings.DNS_TIMEOUT
            resolver.lifetime = settings.DNS_TIMEOUT
            
            # Obtener registros MX ordenados por prioridad
            mx_records = resolver.resolve(domain, 'MX')
            mx_list = sorted(mx_records, key=lambda x: x.preference)
            
            # Probar con el servidor MX de mayor prioridad
            for mx_record in mx_list:
                mx_host = str(mx_record.exchange).rstrip('.')
                
                try:
                    # Conectar al servidor SMTP
                    server = smtplib.SMTP(timeout=settings.SMTP_TIMEOUT)
                    server.set_debuglevel(0)
                    
                    # Conectar y saludar
                    server.connect(mx_host, 25)
                    server.helo('email-validator.com')
                    
                    # Enviar comando MAIL FROM
                    server.mail('noreply@email-validator.com')
                    
                    # Enviar comando RCPT TO (aquí es donde se verifica el email)
                    code, message = server.rcpt(email)
                    
                    result["smtp_code"] = code
                    result["smtp_message"] = message.decode('utf-8') if isinstance(message, bytes) else str(message)
                    
                    # Analizar códigos de respuesta SMTP
                    if code == 250:
                        result["exists"] = True
                        result["deliverable"] = True
                        result["details"].append("Email existe y es entregable")
                        
                    elif code == 251:
                        result["exists"] = True
                        result["deliverable"] = True
                        result["details"].append("Email existe (usuario no local, será reenviado)")
                        
                    elif code == 252:
                        result["exists"] = True
                        result["deliverable"] = True
                        result["catch_all"] = True
                        result["details"].append("Servidor no puede verificar, pero aceptará el email")
                        
                    elif code == 450:
                        result["details"].append("Buzón temporalmente no disponible")
                        
                    elif code == 451:
                        result["details"].append("Error local en procesamiento")
                        
                    elif code == 452:
                        result["mailbox_full"] = True
                        result["details"].append("Buzón lleno - no se pueden aceptar más mensajes")
                        
                    elif code == 550:
                        # Analizar mensaje para más detalles
                        message_lower = result["smtp_message"].lower()
                        if any(keyword in message_lower for keyword in ['mailbox full', 'quota exceeded', 'over quota']):
                            result["mailbox_full"] = True
                            result["details"].append("Buzón lleno")
                        elif any(keyword in message_lower for keyword in ['user unknown', 'no such user', 'invalid recipient']):
                            result["details"].append("Usuario no existe")
                        elif any(keyword in message_lower for keyword in ['relay not permitted', 'relaying denied']):
                            result["details"].append("Retransmisión no permitida")
                        else:
                            result["details"].append("Email rechazado por el servidor")
                            
                    elif code == 551:
                        result["details"].append("Usuario no local")
                        
                    elif code == 552:
                        result["mailbox_full"] = True
                        result["details"].append("Buzón lleno - mensaje excede límite de almacenamiento")
                        
                    elif code == 553:
                        result["details"].append("Nombre de buzón no permitido")
                        
                    elif code == 554:
                        result["details"].append("Transacción falló")
                        
                    else:
                        result["details"].append(f"Código SMTP desconocido: {code}")
                    
                    # Cerrar conexión limpiamente
                    try:
                        server.quit()
                    except:
                        server.close()
                    
                    # Si obtuvimos una respuesta definitiva, salir del bucle
                    if code in [250, 251, 252, 550, 551, 552, 553, 554]:
                        break
                        
                except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, socket.timeout) as e:
                    result["details"].append(f"No se pudo conectar al servidor {mx_host}: {str(e)}")
                    continue
                    
                except smtplib.SMTPException as e:
                    result["details"].append(f"Error SMTP en {mx_host}: {str(e)}")
                    continue
                    
            # Si no pudimos conectar a ningún servidor MX
            if result["smtp_code"] is None:
                result["details"].append("No se pudo conectar a ningún servidor de correo")
                
        except dns.resolver.NXDOMAIN:
            result["details"].append("No se encontraron registros MX para el dominio")
        except Exception as e:
            result["details"].append(f"Error en validación SMTP: {str(e)}")
            logger.error(f"Error en validación SMTP para {email}: {e}")
        
        return result

    @staticmethod
    def is_disposable_email(email: str) -> bool:
        """Verifica si es un email desechable"""
        domain = email.split('@')[1].lower()
        return domain in EmailValidationService.DISPOSABLE_DOMAINS

    @classmethod
    def get_domain_info(cls, domain: str) -> DomainInfo:
        """Obtiene información completa del dominio"""
        domain_exists, a_records = cls.validate_domain_exists(domain)
        has_mx, mx_records = cls.validate_mx_record(domain)
        
        return DomainInfo(
            domain=domain,
            exists=domain_exists,
            has_mx=has_mx,
            mx_records=mx_records,
            a_records=a_records,
            last_checked=time.strftime('%Y-%m-%d %H:%M:%S')
        )

    @classmethod
    def validate_email(cls, request: EmailRequest) -> EmailValidationResult:
        """Valida un correo electrónico completo"""
        start_time = time.time()
        
        result = EmailValidationResult(
            email=request.email,
            is_valid=False,
            format_valid=False,
            domain_exists=False,
            mx_record_exists=False
        )
        
        # Validar formato
        result.format_valid = cls.validate_email_format(request.email)
        if not result.format_valid:
            result.errors.append("Formato de correo inválido")
            result.validation_time = time.time() - start_time
            return result
        
        # Extraer dominio
        domain = request.email.split('@')[1]
        
        # Verificar si es email desechable
        if cls.is_disposable_email(request.email):
            result.warnings.append("Email desechable detectado")
        
        # Validar dominio
        if request.check_domain:
            domain_exists, a_records = cls.validate_domain_exists(domain)
            result.domain_exists = domain_exists
            if not result.domain_exists:
                result.errors.append("El dominio no existe")
            else:
                result.domain_info = {"a_records": a_records}
        
        # Validar registros MX
        if request.check_mx:
            has_mx, mx_records = cls.validate_mx_record(domain)
            result.mx_record_exists = has_mx
            if not result.mx_record_exists:
                result.errors.append("No se encontraron registros MX para el dominio")
            else:
                if result.domain_info is None:
                    result.domain_info = {}
                result.domain_info["mx_records"] = mx_records
        
        # Validar conexión SMTP (opcional)
        if request.check_smtp:
            smtp_result = cls.validate_smtp_connection(request.email)
            result.smtp_valid = smtp_result.get("deliverable", False)
            
            # Crear objeto SMTPValidationResult
            from app.models.email_models import SMTPValidationResult
            result.smtp_details = SMTPValidationResult(
                exists=smtp_result.get("exists", False),
                deliverable=smtp_result.get("deliverable", False),
                mailbox_full=smtp_result.get("mailbox_full", False),
                catch_all=smtp_result.get("catch_all", False),
                smtp_code=smtp_result.get("smtp_code"),
                smtp_message=smtp_result.get("smtp_message", ""),
                details=smtp_result.get("details", [])
            )
            
            # Agregar warnings/errors basados en el resultado SMTP
            if smtp_result.get("mailbox_full", False):
                result.warnings.append("Buzón de correo lleno")
            
            if not smtp_result.get("deliverable", False):
                if smtp_result.get("details"):
                    result.errors.extend(smtp_result["details"])
                else:
                    result.errors.append("No se pudo validar el correo via SMTP")
        
        # Determinar si es válido
        result.is_valid = (
            result.format_valid and
            (not request.check_domain or result.domain_exists) and
            (not request.check_mx or result.mx_record_exists) and
            (not request.check_smtp or result.smtp_valid is not False)
        )
        
        result.validation_time = time.time() - start_time
        return result