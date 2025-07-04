import re
import dns.resolver
import socket
import smtplib
import time
from typing import List, Optional, Dict, Any
from app.models.email_models import EmailValidationResult, EmailRequest, DomainInfo
from app.config.settings import settings
import logging
import asyncio
import concurrent.futures
from email.utils import parseaddr
import ipaddress

logger = logging.getLogger(__name__)

class EmailValidationService:
    
    # Patrones comunes de dominios temporales/desechables (expandido)
    DISPOSABLE_DOMAINS = {
        '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
        'mailinator.com', 'throwaway.email', 'temp-mail.org',
        'yopmail.com', 'maildrop.cc', 'getnada.com', 'sharklasers.com',
        'trashmail.com', 'dispostable.com', 'fakeinbox.com', 'mailcatch.com',
        'mohmal.com', 'emailondeck.com', 'tempail.com', 'deadaddress.com',
        'mytrashmail.com', 'mailexpire.com', 'tempemail.net', 'jetable.org',
        'spamgourmet.com', 'incognitomail.org', 'anonymbox.com', 'mintemail.com'
    }
    
    # Dominios conocidos por tener catch-all
    CATCH_ALL_DOMAINS = {
        'example.com', 'example.org', 'example.net', 'test.com',
        'localhost', 'invalid', 'local'
    }
    
    # Proveedores de email conocidos
    MAJOR_PROVIDERS = {
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
        'aol.com', 'icloud.com', 'protonmail.com', 'zoho.com', 'mail.com'
    }
    
    @staticmethod
    def validate_email_format_advanced(email: str) -> Dict[str, Any]:
        """Validación de formato ultra-avanzada con múltiples verificaciones"""
        result = {
            "is_valid": False,
            "errors": [],
            "warnings": [],
            "details": {},
            "suggestions": []
        }
        
        try:
            # Limpieza inicial
            original_email = email
            email = email.strip().lower()
            
            if not email:
                result["errors"].append("Email vacío")
                return result
            
            # Verificar longitud total
            if len(email) > 254:
                result["errors"].append("Email excede 254 caracteres")
                return result
            
            # Verificar estructura básica
            if email.count('@') != 1:
                result["errors"].append("Debe contener exactamente un símbolo @")
                if '@' not in email:
                    result["suggestions"].append("Agregar símbolo @")
                return result
            
            # Dividir en partes
            local_part, domain = email.split('@')
            
            # Validar parte local
            local_errors = EmailValidationService._validate_local_part(local_part)
            if local_errors:
                result["errors"].extend(local_errors)
            
            # Validar dominio
            domain_errors, domain_suggestions = EmailValidationService._validate_domain_format(domain)
            if domain_errors:
                result["errors"].extend(domain_errors)
            if domain_suggestions:
                result["suggestions"].extend(domain_suggestions)
            
            # Verificaciones adicionales
            result["details"] = {
                "local_part": local_part,
                "domain": domain,
                "local_length": len(local_part),
                "domain_length": len(domain),
                "total_length": len(email),
                "has_plus_addressing": '+' in local_part,
                "has_dots": '.' in local_part,
                "is_quoted": local_part.startswith('"') and local_part.endswith('"')
            }
            
            # Detectar patrones sospechosos
            suspicious_patterns = EmailValidationService._detect_suspicious_patterns(email)
            if suspicious_patterns:
                result["warnings"].extend(suspicious_patterns)
            
            # Si no hay errores, es válido
            result["is_valid"] = len(result["errors"]) == 0
            
            # Usar parseaddr como verificación adicional
            try:
                parsed_name, parsed_email = parseaddr(email)
                if parsed_email != email:
                    result["warnings"].append("Formato no estándar detectado")
            except:
                result["warnings"].append("Error en parsing estándar")
            
        except Exception as e:
            logger.error(f"Error en validación de formato: {e}")
            result["errors"].append(f"Error interno en validación: {str(e)}")
        
        return result

    @staticmethod
    def _validate_local_part(local_part: str) -> List[str]:
        """Valida la parte local del email"""
        errors = []
        
        if not local_part:
            errors.append("Parte local vacía")
            return errors
        
        if len(local_part) > 64:
            errors.append("Parte local excede 64 caracteres")
        
        if local_part.startswith('.') or local_part.endswith('.'):
            errors.append("Parte local no puede empezar o terminar con punto")
        
        if '..' in local_part:
            errors.append("Parte local no puede tener puntos consecutivos")
        
        # Verificar caracteres válidos (sin comillas)
        if not local_part.startswith('"'):
            invalid_chars = set(local_part) - set('abcdefghijklmnopqrstuvwxyz0123456789.!#$%&\'*+-/=?^_`{|}~')
            if invalid_chars:
                errors.append(f"Caracteres inválidos en parte local: {', '.join(invalid_chars)}")
        
        return errors

    @staticmethod
    def _validate_domain_format(domain: str) -> tuple[List[str], List[str]]:
        """Valida el formato del dominio"""
        errors = []
        suggestions = []
        
        if not domain:
            errors.append("Dominio vacío")
            return errors, suggestions
        
        if len(domain) > 253:
            errors.append("Dominio excede 253 caracteres")
        
        if domain.startswith('.') or domain.endswith('.'):
            errors.append("Dominio no puede empezar o terminar con punto")
        
        if '..' in domain:
            errors.append("Dominio no puede tener puntos consecutivos")
        
        # Verificar que tiene al menos un punto
        if '.' not in domain:
            errors.append("Dominio debe contener al menos un punto")
            # Sugerir dominios comunes
            common_domains = ['gmail.com', 'yahoo.com', 'hotmail.com']
            suggestions.extend([f"{domain}.{d}" for d in ['com', 'org', 'net']])
        
        # Verificar TLD
        parts = domain.split('.')
        if len(parts) < 2:
            errors.append("Dominio debe tener al menos un TLD")
        else:
            tld = parts[-1]
            if len(tld) < 2:
                errors.append("TLD debe tener al menos 2 caracteres")
            if not tld.isalpha():
                errors.append("TLD debe contener solo letras")
        
        # Verificar caracteres válidos
        invalid_chars = set(domain) - set('abcdefghijklmnopqrstuvwxyz0123456789.-')
        if invalid_chars:
            errors.append(f"Caracteres inválidos en dominio: {', '.join(invalid_chars)}")
        
        # Detectar errores comunes de tipeo
        typo_suggestions = EmailValidationService._detect_domain_typos(domain)
        suggestions.extend(typo_suggestions)
        
        return errors, suggestions

    @staticmethod
    def _detect_domain_typos(domain: str) -> List[str]:
        """Detecta errores comunes de tipeo en dominios"""
        suggestions = []
        
        # Mapeo de errores comunes
        typo_map = {
            'gmial.com': 'gmail.com',
            'gmai.com': 'gmail.com',
            'gmail.co': 'gmail.com',
            'yahooo.com': 'yahoo.com',
            'yaho.com': 'yahoo.com',
            'hotmial.com': 'hotmail.com',
            'hotmai.com': 'hotmail.com',
            'outlok.com': 'outlook.com',
            'outloo.com': 'outlook.com'
        }
        
        if domain in typo_map:
            suggestions.append(f"¿Quisiste decir {typo_map[domain]}?")
        
        return suggestions

    @staticmethod
    def _detect_suspicious_patterns(email: str) -> List[str]:
        """Detecta patrones sospechosos en el email"""
        warnings = []
        
        # Patrones sospechosos
        suspicious_patterns = [
            (r'(.)\1{4,}', "Contiene caracteres repetidos excesivamente"),
            (r'\d{10,}', "Contiene secuencia numérica muy larga"),
            (r'test.*test', "Parece ser un email de prueba"),
            (r'admin.*admin', "Parece ser un email administrativo genérico"),
            (r'no.*reply', "Parece ser un email de no-respuesta")
        ]
        
        for pattern, message in suspicious_patterns:
            if re.search(pattern, email):
                warnings.append(message)
        
        return warnings

    @staticmethod
    def validate_domain_exists_advanced(domain: str) -> Dict[str, Any]:
        """Verificación avanzada de existencia del dominio con múltiples métodos"""
        result = {
            "exists": False,
            "a_records": [],
            "aaaa_records": [],
            "cname_records": [],
            "ns_records": [],
            "soa_record": None,
            "errors": [],
            "warnings": [],
            "details": {}
        }
        
        try:
            # Crear resolver con configuración robusta
            resolver = dns.resolver.Resolver()
            resolver.timeout = settings.DNS_TIMEOUT
            resolver.lifetime = settings.DNS_TIMEOUT * 2
            
            # Configurar servidores DNS alternativos
            resolver.nameservers = [
                '8.8.8.8',    # Google
                '1.1.1.1',    # Cloudflare
                '208.67.222.222',  # OpenDNS
                '8.8.4.4'     # Google secundario
            ]
            
            # Verificar registros A (IPv4)
            try:
                answers = resolver.resolve(domain, 'A')
                result["a_records"] = [str(answer) for answer in answers]
                result["exists"] = True
            except dns.resolver.NXDOMAIN:
                result["errors"].append("Dominio no existe (NXDOMAIN)")
            except dns.resolver.NoAnswer:
                result["warnings"].append("No hay registros A")
            except Exception as e:
                result["warnings"].append(f"Error consultando registros A: {str(e)}")
            
            # Verificar registros AAAA (IPv6)
            try:
                answers = resolver.resolve(domain, 'AAAA')
                result["aaaa_records"] = [str(answer) for answer in answers]
                if not result["exists"]:
                    result["exists"] = True
            except:
                pass  # IPv6 es opcional
            
            # Verificar CNAME
            try:
                answers = resolver.resolve(domain, 'CNAME')
                result["cname_records"] = [str(answer) for answer in answers]
                if not result["exists"]:
                    result["exists"] = True
            except:
                pass
            
            # Verificar NS records
            try:
                answers = resolver.resolve(domain, 'NS')
                result["ns_records"] = [str(answer) for answer in answers]
            except:
                pass
            
            # Verificar SOA record
            try:
                answers = resolver.resolve(domain, 'SOA')
                result["soa_record"] = str(answers[0])
            except:
                pass
            
            # Información adicional
            result["details"] = {
                "has_ipv4": len(result["a_records"]) > 0,
                "has_ipv6": len(result["aaaa_records"]) > 0,
                "has_cname": len(result["cname_records"]) > 0,
                "nameservers_count": len(result["ns_records"]),
                "resolver_used": resolver.nameservers[0]
            }
            
        except Exception as e:
            logger.error(f"Error en validación avanzada de dominio {domain}: {e}")
            result["errors"].append(f"Error interno: {str(e)}")
        
        return result

    @staticmethod
    def validate_mx_record_advanced(domain: str) -> Dict[str, Any]:
        """Verificación avanzada de registros MX con análisis de prioridad"""
        result = {
            "has_mx": False,
            "mx_records": [],
            "mx_details": [],
            "fallback_a": False,
            "errors": [],
            "warnings": [],
            "analysis": {}
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = settings.DNS_TIMEOUT
            resolver.lifetime = settings.DNS_TIMEOUT * 2
            resolver.nameservers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
            
            # Verificar registros MX
            try:
                mx_records = resolver.resolve(domain, 'MX')
                mx_list = []
                mx_details = []
                
                for record in sorted(mx_records, key=lambda x: x.preference):
                    mx_host = str(record.exchange).rstrip('.')
                    mx_list.append(mx_host)
                    
                    # Verificar que el servidor MX existe
                    mx_exists = False
                    mx_ips = []
                    try:
                        mx_a_records = resolver.resolve(mx_host, 'A')
                        mx_ips = [str(ip) for ip in mx_a_records]
                        mx_exists = True
                    except:
                        pass
                    
                    mx_details.append({
                        "host": mx_host,
                        "priority": record.preference,
                        "exists": mx_exists,
                        "ips": mx_ips
                    })
                
                result["has_mx"] = True
                result["mx_records"] = mx_list
                result["mx_details"] = mx_details
                
                # Análisis de configuración MX
                result["analysis"] = {
                    "mx_count": len(mx_list),
                    "has_backup_mx": len(mx_list) > 1,
                    "lowest_priority": min(r.preference for r in mx_records),
                    "highest_priority": max(r.preference for r in mx_records),
                    "all_mx_valid": all(detail["exists"] for detail in mx_details)
                }
                
                # Verificar configuraciones problemáticas
                if not result["analysis"]["all_mx_valid"]:
                    result["warnings"].append("Algunos servidores MX no existen")
                
                if len(mx_list) == 1:
                    result["warnings"].append("Solo un servidor MX (sin redundancia)")
                
            except dns.resolver.NXDOMAIN:
                result["errors"].append("No se encontraron registros MX")
                
                # Verificar fallback a registro A
                try:
                    resolver.resolve(domain, 'A')
                    result["fallback_a"] = True
                    result["warnings"].append("Sin MX, pero dominio tiene registro A (fallback posible)")
                except:
                    result["errors"].append("Sin registros MX ni A")
                    
            except dns.resolver.NoAnswer:
                result["warnings"].append("Dominio existe pero sin registros MX")
                
            except Exception as e:
                result["errors"].append(f"Error consultando MX: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error en validación MX avanzada para {domain}: {e}")
            result["errors"].append(f"Error interno: {str(e)}")
        
        return result

    @staticmethod
    def validate_smtp_connection_ultra_robust(email: str) -> Dict[str, Any]:
        """Validación SMTP ultra-robusta con múltiples intentos y análisis profundo"""
        result = {
            "exists": False,
            "deliverable": False,
            "mailbox_full": False,
            "catch_all": False,
            "greylisted": False,
            "rate_limited": False,
            "smtp_code": None,
            "smtp_message": "",
            "details": [],
            "attempts": [],
            "server_info": {},
            "security_features": {}
        }
        
        try:
            domain = email.split('@')[1]
            
            # Obtener registros MX con análisis avanzado
            mx_result = EmailValidationService.validate_mx_record_advanced(domain)
            
            if not mx_result["has_mx"] and not mx_result["fallback_a"]:
                result["details"].append("No hay servidores de correo disponibles")
                return result
            
            # Lista de servidores a probar
            servers_to_try = []
            
            if mx_result["has_mx"]:
                # Usar servidores MX ordenados por prioridad
                for mx_detail in mx_result["mx_details"]:
                    if mx_detail["exists"]:
                        servers_to_try.append((mx_detail["host"], 25))
            else:
                # Fallback al dominio directamente
                servers_to_try.append((domain, 25))
            
            # Probar múltiples servidores
            for server_host, port in servers_to_try:
                attempt_result = EmailValidationService._attempt_smtp_connection(
                    server_host, port, email
                )
                result["attempts"].append(attempt_result)
                
                # Si obtuvimos una respuesta definitiva, usar esa
                if attempt_result.get("definitive", False):
                    result.update({
                        "exists": attempt_result.get("exists", False),
                        "deliverable": attempt_result.get("deliverable", False),
                        "mailbox_full": attempt_result.get("mailbox_full", False),
                        "catch_all": attempt_result.get("catch_all", False),
                        "greylisted": attempt_result.get("greylisted", False),
                        "rate_limited": attempt_result.get("rate_limited", False),
                        "smtp_code": attempt_result.get("smtp_code"),
                        "smtp_message": attempt_result.get("smtp_message", ""),
                        "server_info": attempt_result.get("server_info", {}),
                        "security_features": attempt_result.get("security_features", {})
                    })
                    result["details"].extend(attempt_result.get("details", []))
                    break
            
            # Si no obtuvimos respuesta definitiva, usar la mejor disponible
            if not any(attempt.get("definitive", False) for attempt in result["attempts"]):
                best_attempt = max(result["attempts"], 
                                 key=lambda x: x.get("confidence", 0), 
                                 default={})
                if best_attempt:
                    result.update(best_attempt)
            
            # Análisis final
            if not result["attempts"]:
                result["details"].append("No se pudo conectar a ningún servidor de correo")
            
        except Exception as e:
            logger.error(f"Error en validación SMTP ultra-robusta para {email}: {e}")
            result["details"].append(f"Error interno: {str(e)}")
        
        return result

    @staticmethod
    def _attempt_smtp_connection(server_host: str, port: int, email: str) -> Dict[str, Any]:
        """Intenta una conexión SMTP individual con análisis completo"""
        attempt = {
            "server": server_host,
            "port": port,
            "success": False,
            "definitive": False,
            "confidence": 0,
            "exists": False,
            "deliverable": False,
            "mailbox_full": False,
            "catch_all": False,
            "greylisted": False,
            "rate_limited": False,
            "smtp_code": None,
            "smtp_message": "",
            "details": [],
            "server_info": {},
            "security_features": {},
            "timing": {},
            "blocked_reason": None,
            "ip_reputation_issue": False
        }
        
        start_time = time.time()
        
        try:
            # Conectar al servidor SMTP
            server = smtplib.SMTP(timeout=settings.SMTP_TIMEOUT)
            server.set_debuglevel(0)
            
            # Conectar
            connect_start = time.time()
            code, message = server.connect(server_host, port)
            attempt["timing"]["connect"] = time.time() - connect_start
            
            if code != 220:
                attempt["details"].append(f"Conexión rechazada: {code} {message}")
                return attempt
            
            # Obtener información del servidor
            attempt["server_info"]["banner"] = message.decode('utf-8') if isinstance(message, bytes) else str(message)
            
            # HELO/EHLO
            helo_start = time.time()
            try:
                code, message = server.ehlo('email-validator.com')
                attempt["server_info"]["supports_ehlo"] = True
                attempt["server_info"]["extensions"] = server.esmtp_features
                
                # Detectar características de seguridad
                if 'STARTTLS' in server.esmtp_features:
                    attempt["security_features"]["starttls"] = True
                if 'AUTH' in server.esmtp_features:
                    attempt["security_features"]["auth"] = True
                    attempt["security_features"]["auth_methods"] = server.esmtp_features.get('AUTH', '').split()
                
            except:
                code, message = server.helo('email-validator.com')
                attempt["server_info"]["supports_ehlo"] = False
            
            attempt["timing"]["helo"] = time.time() - helo_start
            
            # MAIL FROM
            mail_start = time.time()
            code, message = server.mail('noreply@email-validator.com')
            attempt["timing"]["mail_from"] = time.time() - mail_start
            
            if code not in [250, 251]:
                attempt["details"].append(f"MAIL FROM rechazado: {code} {message}")
                server.quit()
                return attempt
            
            # RCPT TO (la verificación real)
            rcpt_start = time.time()
            code, message = server.rcpt(email)
            attempt["timing"]["rcpt_to"] = time.time() - rcpt_start
            attempt["timing"]["total"] = time.time() - start_time
            
            attempt["smtp_code"] = code
            attempt["smtp_message"] = message.decode('utf-8') if isinstance(message, bytes) else str(message)
            attempt["success"] = True
            
            # Analizar respuesta
            message_lower = attempt["smtp_message"].lower()
            
            if code == 250:
                attempt["exists"] = True
                attempt["deliverable"] = True
                attempt["definitive"] = True
                attempt["confidence"] = 95
                attempt["details"].append("Email existe y es entregable")
                
            elif code == 251:
                attempt["exists"] = True
                attempt["deliverable"] = True
                attempt["definitive"] = True
                attempt["confidence"] = 90
                attempt["details"].append("Email existe (usuario no local, será reenviado)")
                
            elif code == 252:
                attempt["exists"] = True
                attempt["deliverable"] = True
                attempt["catch_all"] = True
                attempt["definitive"] = False
                attempt["confidence"] = 70
                attempt["details"].append("Servidor no puede verificar, pero aceptará el email")
                
            elif code == 450:
                attempt["greylisted"] = True
                attempt["confidence"] = 60
                attempt["details"].append("Buzón temporalmente no disponible (posible greylisting)")
                
            elif code == 451:
                attempt["confidence"] = 40
                attempt["details"].append("Error local en procesamiento")
                
            elif code == 452:
                attempt["mailbox_full"] = True
                attempt["exists"] = True
                attempt["definitive"] = True
                attempt["confidence"] = 85
                attempt["details"].append("Buzón lleno - no se pueden aceptar más mensajes")
                
            elif code == 421:
                attempt["rate_limited"] = True
                attempt["confidence"] = 30
                attempt["details"].append("Servicio temporalmente no disponible (rate limiting)")
                
            elif code == 550:
                attempt["definitive"] = True
                attempt["confidence"] = 90
                
                # Análisis específico para diferentes tipos de bloqueo
                if any(keyword in message_lower for keyword in ['spamhaus', 'blacklist', 'blocklist', 'rbl']):
                    attempt["ip_reputation_issue"] = True
                    attempt["blocked_reason"] = "IP en lista negra (RBL/Spamhaus)"
                    attempt["details"].append("IP bloqueada por reputación - no indica problema con el email")
                    attempt["confidence"] = 75  # Alta confianza de que el email es válido
                    
                elif any(keyword in message_lower for keyword in ['client host', 'blocked using']):
                    attempt["ip_reputation_issue"] = True
                    attempt["blocked_reason"] = "Host cliente bloqueado"
                    attempt["details"].append("Cliente bloqueado por políticas del servidor")
                    attempt["confidence"] = 70
                    
                elif any(keyword in message_lower for keyword in ['mailbox full', 'quota exceeded', 'over quota']):
                    attempt["mailbox_full"] = True
                    attempt["exists"] = True
                    attempt["details"].append("Buzón lleno")
                    
                elif any(keyword in message_lower for keyword in ['user unknown', 'no such user', 'invalid recipient', 'user not found']):
                    attempt["details"].append("Usuario no existe")
                    
                elif any(keyword in message_lower for keyword in ['relay not permitted', 'relaying denied']):
                    attempt["details"].append("Retransmisión no permitida")
                    
                elif any(keyword in message_lower for keyword in ['spam', 'blocked', 'blacklist']):
                    attempt["details"].append("Email bloqueado por políticas anti-spam")
                    
                else:
                    attempt["details"].append("Email rechazado por el servidor")
                    
            elif code == 551:
                attempt["definitive"] = True
                attempt["confidence"] = 85
                attempt["details"].append("Usuario no local")
                
            elif code == 552:
                attempt["mailbox_full"] = True
                attempt["exists"] = True
                attempt["definitive"] = True
                attempt["confidence"] = 90
                attempt["details"].append("Buzón lleno - mensaje excede límite de almacenamiento")
                
            elif code == 553:
                attempt["definitive"] = True
                attempt["confidence"] = 85
                attempt["details"].append("Nombre de buzón no permitido")
                
            elif code == 554:
                attempt["definitive"] = True
                attempt["confidence"] = 80
                attempt["details"].append("Transacción falló")
                
            else:
                attempt["confidence"] = 30
                attempt["details"].append(f"Código SMTP desconocido: {code}")
            
            # Cerrar conexión
            try:
                server.quit()
            except:
                server.close()
                
        except socket.timeout:
            attempt["details"].append(f"Timeout conectando a {server_host}")
            attempt["confidence"] = 10
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected):
            attempt["details"].append(f"No se pudo conectar al servidor {server_host}")
            attempt["confidence"] = 20
        except smtplib.SMTPException as e:
            attempt["details"].append(f"Error SMTP: {str(e)}")
            attempt["confidence"] = 15
        except Exception as e:
            attempt["details"].append(f"Error inesperado: {str(e)}")
            attempt["confidence"] = 5
        
        attempt["timing"]["total"] = time.time() - start_time
        return attempt

    @staticmethod
    def validate_email_format(email: str) -> bool:
        """Versión simple para compatibilidad"""
        result = EmailValidationService.validate_email_format_advanced(email)
        return result["is_valid"]

    @staticmethod
    def validate_domain_exists(domain: str) -> tuple[bool, List[str]]:
        """Versión simple para compatibilidad"""
        result = EmailValidationService.validate_domain_exists_advanced(domain)
        return result["exists"], result["a_records"]

    @staticmethod
    def validate_mx_record(domain: str) -> tuple[bool, List[str]]:
        """Versión simple para compatibilidad"""
        result = EmailValidationService.validate_mx_record_advanced(domain)
        return result["has_mx"], result["mx_records"]

    @staticmethod
    def validate_smtp_connection(email: str) -> dict:
        """Versión simple que retorna el resultado completo"""
        return EmailValidationService.validate_smtp_connection_ultra_robust(email)

    @staticmethod
    def is_disposable_email(email: str) -> bool:
        """Verifica si es un email desechable con base expandida"""
        domain = email.split('@')[1].lower()
        return domain in EmailValidationService.DISPOSABLE_DOMAINS

    @classmethod
    def get_domain_info(cls, domain: str) -> DomainInfo:
        """Obtiene información completa del dominio"""
        domain_result = cls.validate_domain_exists_advanced(domain)
        mx_result = cls.validate_mx_record_advanced(domain)
        
        return DomainInfo(
            domain=domain,
            exists=domain_result["exists"],
            has_mx=mx_result["has_mx"],
            mx_records=mx_result["mx_records"],
            a_records=domain_result["a_records"],
            last_checked=time.strftime('%Y-%m-%d %H:%M:%S')
        )

    @classmethod
    def validate_email_ultra_deep(cls, email: str) -> Dict[str, Any]:
        """Validación ultra-profunda que nunca falla"""
        start_time = time.time()
        
        # Resultado base que nunca falla
        result = {
            "email": email.strip().lower() if email else "",
            "is_valid": False,
            "confidence_score": 0,
            "validation_level": "ultra_deep",
            "format_analysis": {},
            "domain_analysis": {},
            "mx_analysis": {},
            "smtp_analysis": {},
            "security_analysis": {},
            "recommendations": [],
            "errors": [],
            "warnings": [],
            "processing_time": 0
        }
        
        try:
            # 1. Análisis de formato avanzado
            try:
                format_result = cls.validate_email_format_advanced(email)
                result["format_analysis"] = format_result
                if format_result["is_valid"]:
                    result["confidence_score"] += 20
                else:
                    result["errors"].extend(format_result["errors"])
                    result["warnings"].extend(format_result["warnings"])
                    # Si el formato es inválido, no continuar con otras validaciones
                    result["processing_time"] = time.time() - start_time
                    return result
            except Exception as e:
                result["errors"].append(f"Error en análisis de formato: {str(e)}")
                result["processing_time"] = time.time() - start_time
                return result
            
            # Extraer dominio
            domain = email.split('@')[1] if '@' in email else ""
            
            # 2. Análisis de dominio avanzado
            try:
                domain_result = cls.validate_domain_exists_advanced(domain)
                result["domain_analysis"] = domain_result
                if domain_result["exists"]:
                    result["confidence_score"] += 25
                else:
                    result["errors"].extend(domain_result["errors"])
                    result["warnings"].extend(domain_result["warnings"])
            except Exception as e:
                result["warnings"].append(f"Error en análisis de dominio: {str(e)}")
            
            # 3. Análisis MX avanzado
            try:
                mx_result = cls.validate_mx_record_advanced(domain)
                result["mx_analysis"] = mx_result
                if mx_result["has_mx"] or mx_result["fallback_a"]:
                    result["confidence_score"] += 20
                else:
                    result["errors"].extend(mx_result["errors"])
                    result["warnings"].extend(mx_result["warnings"])
            except Exception as e:
                result["warnings"].append(f"Error en análisis MX: {str(e)}")
            
            # 4. Análisis SMTP ultra-robusto
            try:
                smtp_result = cls.validate_smtp_connection_ultra_robust(email)
                result["smtp_analysis"] = smtp_result
                
                # Verificar si hay problemas de reputación de IP
                ip_reputation_issue = any(
                    attempt.get("ip_reputation_issue", False) 
                    for attempt in smtp_result.get("attempts", [])
                )
                
                if smtp_result["deliverable"]:
                    result["confidence_score"] += 35
                elif smtp_result["exists"]:
                    result["confidence_score"] += 25
                    if smtp_result["mailbox_full"]:
                        result["warnings"].append("Buzón de correo lleno")
                elif ip_reputation_issue:
                    # Si hay problema de reputación de IP, el email probablemente es válido
                    result["confidence_score"] += 20
                    result["warnings"].append("Verificación SMTP limitada por reputación de IP del validador")
                    
            except Exception as e:
                result["warnings"].append(f"Error en análisis SMTP: {str(e)}")
            
            # 5. Análisis de seguridad
            try:
                security_analysis = {
                    "is_disposable": cls.is_disposable_email(email),
                    "is_catch_all": smtp_result.get("catch_all", False),
                    "is_major_provider": domain in cls.MAJOR_PROVIDERS,
                    "has_security_features": bool(smtp_result.get("security_features", {})),
                    "suspicious_patterns": format_result.get("warnings", [])
                }
                result["security_analysis"] = security_analysis
                
                if security_analysis["is_disposable"]:
                    result["warnings"].append("Email desechable detectado")
                    result["confidence_score"] -= 10
                
                if security_analysis["is_major_provider"]:
                    result["confidence_score"] += 5
                    
            except Exception as e:
                result["warnings"].append(f"Error en análisis de seguridad: {str(e)}")
            
            # 6. Generar recomendaciones
            try:
                recommendations = []
                
                # Verificar si hay problemas de reputación de IP
                ip_reputation_issue = any(
                    attempt.get("ip_reputation_issue", False) 
                    for attempt in smtp_result.get("attempts", [])
                )
                
                if result["confidence_score"] >= 80:
                    recommendations.append("✅ Email altamente confiable para uso en producción")
                elif result["confidence_score"] >= 60:
                    if ip_reputation_issue:
                        recommendations.append("✅ Email probablemente válido - Limitación por IP del validador, no del email")
                        recommendations.append("💡 Recomendación: Usar desde IP con mejor reputación para verificación completa")
                    else:
                        recommendations.append("✅ Email probablemente válido, verificar manualmente si es crítico")
                elif result["confidence_score"] >= 40:
                    recommendations.append("⚠️ Email dudoso, considerar validación adicional")
                else:
                    recommendations.append("❌ Email no recomendado para uso")
                
                # Recomendaciones específicas
                if smtp_result.get("mailbox_full"):
                    recommendations.append("📧 Reintentar más tarde cuando el buzón esté disponible")
                
                if security_analysis.get("is_disposable"):
                    recommendations.append("🗑️ Considerar rechazar emails desechables según política")
                
                if ip_reputation_issue:
                    blocked_reason = smtp_result.get("attempts", [{}])[0].get("blocked_reason", "")
                    if blocked_reason:
                        recommendations.append(f"🔒 Bloqueo detectado: {blocked_reason}")
                    recommendations.append("🌐 Usar validador desde IP con mejor reputación para resultados más precisos")
                
                # Información sobre el dominio
                if domain_result.get("exists") and mx_result.get("has_mx"):
                    if security_analysis.get("is_major_provider"):
                        recommendations.append("🏢 Dominio de proveedor principal reconocido")
                    else:
                        recommendations.append("🏛️ Dominio institucional/empresarial con infraestructura propia")
                
                if format_result.get("suggestions"):
                    recommendations.extend(format_result["suggestions"])
                
                result["recommendations"] = recommendations
                
            except Exception as e:
                result["warnings"].append(f"Error generando recomendaciones: {str(e)}")
            
            # 7. Determinar validez final
            result["is_valid"] = (
                result["confidence_score"] >= 60 and
                len(result["errors"]) == 0 and
                not any("formato" in error.lower() for error in result["errors"])
            )
            
        except Exception as e:
            # Captura cualquier error no manejado
            result["errors"].append(f"Error interno en validación ultra-profunda: {str(e)}")
            logger.error(f"Error en validate_email_ultra_deep para {email}: {e}")
        
        finally:
            # Siempre calcular tiempo de procesamiento
            result["processing_time"] = time.time() - start_time
            
            # Asegurar que confidence_score esté en rango válido
            result["confidence_score"] = max(0, min(100, result["confidence_score"]))
        
        return result

    @classmethod
    def validate_email(cls, request: EmailRequest) -> EmailValidationResult:
        """Validación estándar mejorada"""
        start_time = time.time()
        
        result = EmailValidationResult(
            email=request.email,
            is_valid=False,
            format_valid=False,
            domain_exists=False,
            mx_record_exists=False
        )
        
        try:
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
            
        except Exception as e:
            logger.error(f"Error en validación de email {request.email}: {e}")
            result.errors.append(f"Error interno: {str(e)}")
        
        finally:
            result.validation_time = time.time() - start_time
        
        return result