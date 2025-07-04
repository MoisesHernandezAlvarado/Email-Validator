# 📧 Email Validator API

Una API REST avanzada para validación de correos electrónicos construida con FastAPI. Ofrece múltiples niveles de validación desde formato básico hasta verificación SMTP profunda con detección de bandeja llena.

## 🚀 Características Principales

- ✅ **Validación de Formato**: Regex RFC-compliant con verificaciones adicionales
- 🌐 **Verificación de Dominio**: Consultas DNS para verificar existencia
- 📮 **Registros MX**: Verificación de servidores de correo
- 🔍 **Validación SMTP Profunda**: Verificación real de existencia y bandeja llena
- 📊 **Procesamiento en Lotes**: Hasta 100 emails simultáneamente
- 📁 **Carga de CSV**: Endpoint para procesar archivos CSV
- 🚫 **Detección de Emails Desechables**: Base de datos de dominios temporales
- 📈 **Estadísticas Detalladas**: Métricas completas de validación
- 🔧 **API RESTful**: Documentación automática con Swagger/OpenAPI

## 📋 Tabla de Contenidos

- [Instalación](#-instalación)
- [Configuración](#-configuración)
- [Uso Rápido](#-uso-rápido)
- [Endpoints de la API](#-endpoints-de-la-api)
- [Ejemplos de Uso](#-ejemplos-de-uso)
- [Procesamiento de CSV](#-procesamiento-de-csv)
- [Validación SMTP Avanzada](#-validación-smtp-avanzada)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Configuración Avanzada](#-configuración-avanzada)
- [Testing](#-testing)
- [Contribuir](#-contribuir)

## 🛠️ Instalación

### Requisitos Previos

- Python 3.8+
- pip

### Instalación Rápida

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/email-validator-api.git
cd email-validator-api

# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
# En Windows:
venv\Scripts\activate
# En macOS/Linux:
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar la aplicación
python run.py
```

La API estará disponible en `http://localhost:8000`

## ⚙️ Configuración

### Variables de Entorno

Crea un archivo `.env` en la raíz del proyecto:

```env
# Configuración de la aplicación
APP_NAME=Email Validator API
APP_VERSION=1.0.0
DEBUG=true
HOST=0.0.0.0
PORT=8000
LOG_LEVEL=INFO

# Configuración de validación
MAX_BATCH_SIZE=100
SMTP_TIMEOUT=10
DNS_TIMEOUT=5

# Rate limiting (opcional)
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_PERIOD=60
```

### Configuración por Defecto

Si no se especifica un archivo `.env`, se usarán los valores por defecto definidos en `app/config/settings.py`.

## 🚀 Uso Rápido

### Iniciar el Servidor

```bash
python run.py
```

### Acceder a la Documentación

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

### Ejemplo Básico

```bash
# Validación simple
curl "http://localhost:8000/api/v1/email/validate-simple/test@gmail.com"

# Validación completa
curl -X POST "http://localhost:8000/api/v1/email/validate" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": true}'
```

## 🔗 Endpoints de la API

### Validación Individual

| Endpoint | Método | Descripción |
|----------|---------|-------------|
| `/api/v1/email/validate` | POST | Validación completa configurable |
| `/api/v1/email/validate-simple/{email}` | GET | Validación rápida de formato |
| `/api/v1/email/validate-deep/{email}` | GET | Validación SMTP profunda |

### Validación en Lotes

| Endpoint | Método | Descripción |
|----------|---------|-------------|
| `/api/v1/email/validate-batch` | POST | Validación de múltiples emails |
| `/api/v1/email/validate-csv` | POST | Procesamiento de archivos CSV |

### Información y Utilidades

| Endpoint | Método | Descripción |
|----------|---------|-------------|
| `/api/v1/email/domain-info/{domain}` | GET | Información detallada del dominio |
| `/api/v1/email/stats` | GET | Estadísticas del servicio |
| `/api/v1/email/health` | GET | Estado de salud del servicio |

## 📖 Ejemplos de Uso

### 1. Validación Individual Básica

```bash
curl -X POST "http://localhost:8000/api/v1/email/validate" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "usuario@ejemplo.com",
    "check_domain": true,
    "check_mx": true,
    "check_smtp": false
  }'
```

**Respuesta:**
```json
{
  "email": "usuario@ejemplo.com",
  "is_valid": true,
  "format_valid": true,
  "domain_exists": true,
  "mx_record_exists": true,
  "smtp_valid": null,
  "errors": [],
  "warnings": [],
  "validation_time": 0.245,
  "domain_info": {
    "a_records": ["192.168.1.1"],
    "mx_records": ["mail.ejemplo.com"]
  }
}
```

### 2. Validación SMTP Profunda

```bash
curl "http://localhost:8000/api/v1/email/validate-deep/test@gmail.com"
```

**Respuesta:**
```json
{
  "email": "test@gmail.com",
  "is_valid": false,
  "format_valid": true,
  "domain_exists": true,
  "mx_record_exists": true,
  "smtp_valid": false,
  "validation_time": 3.24,
  "errors": ["Usuario no existe"],
  "warnings": [],
  "validation_type": "deep_smtp",
  "smtp_details": {
    "email_exists": false,
    "deliverable": false,
    "mailbox_full": false,
    "catch_all": false,
    "smtp_code": 550,
    "smtp_message": "5.1.1 User unknown",
    "details": ["Usuario no existe"]
  }
}
```

### 3. Validación en Lotes

```bash
curl -X POST "http://localhost:8000/api/v1/email/validate-batch" \
  -H "Content-Type: application/json" \
  -d '{
    "emails": [
      "test1@gmail.com",
      "test2@yahoo.com",
      "invalid@nonexistent.com"
    ],
    "check_domain": true,
    "check_mx": true,
    "check_smtp": false
  }'
```

### 4. Información de Dominio

```bash
curl "http://localhost:8000/api/v1/email/domain-info/gmail.com"
```

**Respuesta:**
```json
{
  "domain": "gmail.com",
  "exists": true,
  "has_mx": true,
  "mx_records": [
    "gmail-smtp-in.l.google.com.",
    "alt1.gmail-smtp-in.l.google.com."
  ],
  "a_records": ["142.250.191.109"],
  "last_checked": "2024-01-15 10:30:45"
}
```

## 📁 Procesamiento de CSV

### Subir Archivo CSV

```bash
curl -X POST "http://localhost:8000/api/v1/email/validate-csv" \
  -F "file=@emails.csv" \
  -F "check_domain=true" \
  -F "check_mx=true" \
  -F "batch_size=50"
```

### Formato del CSV

El archivo CSV debe contener una columna con emails. El sistema detecta automáticamente columnas con nombres como:
- `email`
- `correo`
- `mail`
- `e-mail`

**Ejemplo de CSV:**
```csv
email
usuario1@gmail.com
usuario2@yahoo.com
usuario3@hotmail.com
```

### Parámetros del Endpoint CSV

| Parámetro | Tipo | Descripción | Por Defecto |
|-----------|------|-------------|-------------|
| `file` | File | Archivo CSV (requerido) | - |
| `email_column` | String | Nombre de la columna con emails | Auto-detecta |
| `check_domain` | Boolean | Verificar dominio | `true` |
| `check_mx` | Boolean | Verificar registros MX | `true` |
| `check_smtp` | Boolean | Verificar SMTP | `false` |
| `batch_size` | Integer | Tamaño del lote (1-100) | `50` |

## 🔍 Validación SMTP Avanzada

### Códigos SMTP Soportados

| Código | Estado | Descripción |
|--------|--------|-------------|
| 250 | ✅ Válido | Email existe y es entregable |
| 251 | ✅ Válido | Email existe (será reenviado) |
| 252 | ⚠️ Incierto | Servidor no puede verificar |
| 450 | ⚠️ Temporal | Buzón temporalmente no disponible |
| 452 | 📮 Lleno | Buzón lleno |
| 550 | ❌ Inválido | Email rechazado |
| 552 | 📮 Lleno | Buzón lleno - excede límite |
| 553 | ❌ Inválido | Nombre de buzón no permitido |
| 554 | ❌ Error | Transacción falló |

### Detección de Bandeja Llena

El sistema detecta bandeja llena mediante:
- **Códigos SMTP**: 452, 552
- **Mensajes**: "mailbox full", "quota exceeded", "over quota"

### Ejemplo de Bandeja Llena

```json
{
  "email": "usuario@ejemplo.com",
  "is_valid": false,
  "smtp_details": {
    "email_exists": true,
    "deliverable": false,
    "mailbox_full": true,
    "smtp_code": 452,
    "smtp_message": "Requested action not taken: mailbox full",
    "details": ["Buzón lleno - no se pueden aceptar más mensajes"]
  },
  "warnings": ["Buzón de correo lleno"]
}
```

## 🏗️ Estructura del Proyecto

```
email-validator-api/
├── app/
│   ├── __init__.py
│   ├── main.py                 # Aplicación FastAPI principal
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py         # Configuración y variables de entorno
│   ├── models/
│   │   ├── __init__.py
│   │   └── email_models.py     # Modelos Pydantic
│   ├── routers/
│   │   ├── __init__.py
│   │   └── email_router.py     # Endpoints de la API
│   ├── services/
│   │   ├── __init__.py
│   │   └── email_service.py    # Lógica de validación
│   ├── utils/
│   │   ├── __init__.py
│   │   └── validator.py        # Utilidades de validación
│   └── test/
│       ├── __init__.py
│       ├── test_email_validation.py
│       └── test_main.py
├── csv_email_validator.py      # Script independiente para CSV
├── ejemplo_emails.csv          # Archivo de ejemplo
├── requirements.txt            # Dependencias
├── run.py                     # Script de inicio
└── README.md                  # Este archivo
```

## 🔧 Configuración Avanzada

### Personalizar Dominios Desechables

Edita `app/services/email_service.py`:

```python
DISPOSABLE_DOMAINS = {
    '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
    'mailinator.com', 'throwaway.email', 'temp-mail.org',
    # Agregar más dominios aquí
    'tu-dominio-temporal.com'
}
```

### Configurar Timeouts

En `.env` o `app/config/settings.py`:

```python
SMTP_TIMEOUT = 10  # Timeout para conexiones SMTP
DNS_TIMEOUT = 5    # Timeout para consultas DNS
```

### Límites de Lotes

```python
MAX_BATCH_SIZE = 100  # Máximo emails por lote
```

## 🧪 Testing

### Ejecutar Tests

```bash
# Ejecutar todos los tests
python -m pytest app/test/

# Ejecutar tests específicos
python -m pytest app/test/test_email_validation.py

# Ejecutar con cobertura
python -m pytest app/test/ --cov=app
```

### Tests Incluidos

- ✅ Validación de formato de emails
- ✅ Verificación de dominios
- ✅ Consultas MX
- ✅ Validación SMTP
- ✅ Procesamiento en lotes
- ✅ Endpoints de la API

## 📊 Métricas y Monitoreo

### Endpoint de Estadísticas

```bash
curl "http://localhost:8000/api/v1/email/stats"
```

**Respuesta:**
```json
{
  "service": "Email Validation API",
  "version": "1.0.0",
  "max_batch_size": 100,
  "smtp_timeout": 10,
  "dns_timeout": 5,
  "disposable_domains_count": 6
}
```

### Health Check

```bash
curl "http://localhost:8000/api/v1/email/health"
```

## 🚀 Despliegue

### Docker (Recomendado)

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["python", "run.py"]
```

### Despliegue Manual

```bash
# Instalar dependencias del sistema
sudo apt-get update
sudo apt-get install python3-pip

# Instalar la aplicación
pip install -r requirements.txt

# Ejecutar con Gunicorn (producción)
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

## 📈 Rendimiento

### Benchmarks Típicos

- **Validación de formato**: ~0.001s por email
- **Verificación DNS**: ~0.050s por dominio
- **Validación SMTP**: ~2-5s por email
- **Procesamiento en lotes**: ~50 emails/minuto (con SMTP)

### Optimizaciones

- Usa `check_smtp=false` para validación rápida
- Procesa en lotes para mejor rendimiento
- Implementa caché para dominios frecuentes
- Usa conexiones persistentes para SMTP

## 🔒 Seguridad

### Buenas Prácticas

- ✅ Validación de entrada estricta
- ✅ Timeouts configurables
- ✅ Rate limiting (configurable)
- ✅ Logging de errores
- ✅ Manejo seguro de excepciones

### Consideraciones de Producción

- Implementar autenticación/autorización
- Configurar HTTPS
- Usar rate limiting
- Monitorear logs
- Implementar caché Redis

## 🐛 Solución de Problemas

### Errores Comunes

**Error: "NoneType object has no attribute 'timeout'"**
```bash
# Solución: Actualizar dnspython
pip install --upgrade dnspython
```

**Error: "Connection timeout"**
```bash
# Ajustar timeouts en settings.py
SMTP_TIMEOUT = 30
DNS_TIMEOUT = 10
```

**Error: "Too many requests"**
```bash
# Reducir batch_size o implementar delays
```

### Logs

Los logs se configuran en `run.py`:

```python
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

## 🤝 Contribuir

### Cómo Contribuir

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

### Reportar Bugs

Usa el sistema de issues de GitHub con:
- Descripción del problema
- Pasos para reproducir
- Comportamiento esperado vs actual
- Versión de Python y dependencias

## 📝 Changelog

### v1.0.0 (2024-01-15)
- ✅ Validación de formato RFC-compliant
- ✅ Verificación DNS y MX
- ✅ Validación SMTP básica
- ✅ Procesamiento en lotes
- ✅ Endpoint para CSV
- ✅ Validación SMTP avanzada
- ✅ Detección de bandeja llena
- ✅ Documentación completa

## 📄 Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## 👥 Autores

- **Tu Nombre** - *Desarrollo inicial* - [tu-usuario](https://github.com/tu-usuario)

## 🙏 Agradecimientos

- [FastAPI](https://fastapi.tiangolo.com/) - Framework web moderno
- [Pydantic](https://pydantic-docs.helpmanual.io/) - Validación de datos
- [dnspython](https://dnspython.readthedocs.io/) - Consultas DNS
- [Pandas](https://pandas.pydata.org/) - Procesamiento de datos

---

## 📞 Soporte

Si tienes preguntas o necesitas ayuda:

- 📧 Email: tu-email@example.com
- 💬 Issues: [GitHub Issues](https://github.com/tu-usuario/email-validator-api/issues)
- 📖 Documentación: `http://localhost:8000/docs`

---

**¡Gracias por usar Email Validator API!** 🚀
