-- =====================================================================
-- BaxterSec - Datos base (catálogos)
-- Pegar en: supabase/seed.sql
-- Es idempotente: se puede ejecutar varias veces sin duplicar filas.
-- Los pesos y severidades son un punto de partida: ajústalos con tu
-- equipo según la metodología de puntaje que definan.
-- =====================================================================

-- ---------------------------------------------------------------------
-- Fuentes OSINT
-- tipo_acceso: 'publica' (sin llave) | 'api_key' (requiere llave)
-- ---------------------------------------------------------------------
INSERT INTO public.fuentes_osint (nombre, tipo_acceso) VALUES
    ('Shodan',       'api_key'),
    ('SpiderFoot',   'herramienta_local'),
    ('theHarvester', 'herramienta_local'),
    ('crt.sh',       'publica')
ON CONFLICT (nombre) DO UPDATE
    SET tipo_acceso = EXCLUDED.tipo_acceso;
-- ---------------------------------------------------------------------
-- Reglas de riesgo
-- categoria coincide con las dimensiones de puntajes_riesgo:
--   infraestructura | identidad_digital | configuracion | fuga_de_datos
-- severidad: baja | media | alta | critica
-- ---------------------------------------------------------------------
INSERT INTO public.reglas_riesgo
    (codigo, nombre, descripcion, tipo_activo, categoria, severidad, peso)
VALUES
    -- Infraestructura
    ('INFRA-001', 'Puerto de administración remota expuesto',
     'Servicios como RDP o SSH accesibles desde internet.',
     'ip', 'infraestructura', 'alta', 20),
    ('INFRA-002', 'Base de datos expuesta a internet',
     'Puerto de un motor de base de datos accesible públicamente.',
     'ip', 'infraestructura', 'critica', 30),
    ('INFRA-003', 'Software con versión obsoleta',
     'Servicio con una versión sin soporte o con vulnerabilidades conocidas.',
     'servicio', 'infraestructura', 'media', 10),
    ('INFRA-004', 'Subdominio susceptible a takeover',
     'Registro DNS apuntando a un recurso externo que ya no existe.',
     'subdominio', 'infraestructura', 'alta', 20),

    -- Configuración
    ('CONF-001', 'Certificado TLS expirado',
     'El certificado del dominio ya expiró.',
     'dominio', 'configuracion', 'alta', 15),
    ('CONF-002', 'Certificado TLS próximo a expirar',
     'El certificado expira en menos de 30 días.',
     'dominio', 'configuracion', 'media', 8),
    ('CONF-003', 'Registros SPF/DKIM/DMARC ausentes o débiles',
     'El dominio puede ser suplantado en correos electrónicos.',
     'dominio', 'configuracion', 'media', 10),
    ('CONF-004', 'Cabeceras de seguridad HTTP ausentes',
     'Faltan cabeceras como HSTS, CSP o X-Content-Type-Options.',
     'dominio', 'configuracion', 'baja', 5),
    ('CONF-005', 'Protocolo TLS obsoleto habilitado',
     'El servidor acepta TLS 1.0 o 1.1.',
     'dominio', 'configuracion', 'media', 10),

    -- Identidad digital
    ('IDEN-001', 'Correo corporativo en filtración de credenciales',
     'Una cuenta de la organización aparece en una filtración pública.',
     'correo', 'identidad_digital', 'alta', 25),
    ('IDEN-002', 'Dominio similar registrado (typosquatting)',
     'Existe un dominio parecido al de la organización que podría usarse para phishing.',
     'dominio', 'identidad_digital', 'media', 10),
    ('IDEN-003', 'Correos corporativos expuestos públicamente',
     'Direcciones de la organización publicadas en fuentes abiertas.',
     'correo', 'identidad_digital', 'baja', 5),

    -- Fuga de datos
    ('FUGA-001', 'Credenciales o llaves API en repositorio público',
     'Secretos de la organización publicados en código abierto.',
     'dominio', 'fuga_de_datos', 'critica', 30),
    ('FUGA-002', 'Documentos internos indexados en buscadores',
     'Archivos que no deberían ser públicos aparecen en resultados de búsqueda.',
     'dominio', 'fuga_de_datos', 'media', 12),
    ('FUGA-003', 'Almacenamiento en la nube público',
     'Bucket o contenedor accesible sin autenticación.',
     'servicio', 'fuga_de_datos', 'critica', 30),
    ('FUGA-004', 'Datos de la organización en sitios de pegado',
     'Información de la organización publicada en servicios tipo paste.',
     'dominio', 'fuga_de_datos', 'alta', 20)
ON CONFLICT (codigo) DO UPDATE SET
    nombre      = EXCLUDED.nombre,
    descripcion = EXCLUDED.descripcion,
    tipo_activo = EXCLUDED.tipo_activo,
    categoria   = EXCLUDED.categoria,
    severidad   = EXCLUDED.severidad,
    peso        = EXCLUDED.peso;
