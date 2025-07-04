import re
from typing import List, Dict, Any

class ValidatorUtils:
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Valida si un dominio tiene formato válido"""
        if not domain or len(domain) > 253:
            return False
        
        # Patrón para validar dominios
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(pattern, domain) is not None
    
    @staticmethod
    def clean_email(email: str) -> str:
        """Limpia y normaliza un email"""
        if not email:
            return ""
        
        # Remover espacios y convertir a minúsculas
        email = email.strip().lower()
        
        # Remover caracteres no válidos al inicio y final
        email = email.strip('.')
        
        return email
    
    @staticmethod
    def extract_domain(email: str) -> str:
        """Extrae el dominio de un email"""
        if '@' not in email:
            return ""
        
        return email.split('@')[1]
    
    @staticmethod
    def validate_email_list(emails: List[str]) -> Dict[str, Any]:
        """Valida una lista de emails y retorna estadísticas"""
        stats = {
            "total": len(emails),
            "valid_format": 0,
            "invalid_format": 0,
            "duplicates": 0,
            "empty": 0,
            "cleaned_emails": [],
            "invalid_emails": []
        }
        
        seen_emails = set()
        
        for email in emails:
            if not email or not email.strip():
                stats["empty"] += 1
                continue
            
            cleaned = ValidatorUtils.clean_email(email)
            
            if cleaned in seen_emails:
                stats["duplicates"] += 1
                continue
            
            seen_emails.add(cleaned)
            
            # Validar formato básico
            if '@' in cleaned and '.' in cleaned.split('@')[1]:
                stats["valid_format"] += 1
                stats["cleaned_emails"].append(cleaned)
            else:
                stats["invalid_format"] += 1
                stats["invalid_emails"].append(cleaned)
        
        return stats
    
    @staticmethod
    def get_common_domains(emails: List[str]) -> Dict[str, int]:
        """Obtiene los dominios más comunes de una lista de emails"""
        domain_count = {}
        
        for email in emails:
            if '@' in email:
                domain = ValidatorUtils.extract_domain(email)
                domain_count[domain] = domain_count.get(domain, 0) + 1
        
        # Ordenar por frecuencia
        return dict(sorted(domain_count.items(), key=lambda x: x[1], reverse=True))
