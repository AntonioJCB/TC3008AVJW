# CA local para SpiderFoot

Este directorio se monta en `/opt/baxtersec-ca` como solo lectura. Si la red
inspecciona TLS, exporta únicamente el certificado raíz público de la CA
institucional en formato PEM, guárdalo aquí y configura en `spiderfoot.env`:

```dotenv
SPIDERFOOT_CA_BUNDLE=/opt/baxtersec-ca/raiz-institucional.pem
```

Los archivos `.pem` y `.crt` están ignorados por Git. No guardes claves privadas
ni desactives la verificación TLS. En despliegues sin inspección HTTPS deja la
variable vacía para usar el almacén normal de `certifi`.
