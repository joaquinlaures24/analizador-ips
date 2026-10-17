# Analizador de IPs para reportes de aplicaciones expuestas

Herramienta de línea de comandos en Python que automatiza el análisis diario de IPs atacantes en un SOC. Toma los exports CSV de Wazuh (Visualize/Kibana), consulta la reputación de cada IP en [AbuseIPDB](https://www.abuseipdb.com/) y genera un Excel listo para armar el reporte al cliente.

> **Contexto:** nació de una tarea manual repetitiva: exportar eventos de Wazuh, unir tablas en Excel, pasar cada IP una por una por AbuseIPDB y validar a mano contra la whitelist de cada cliente. Con esta herramienta el proceso pasa de decenas de minutos por cliente a pocos minutos. **El analista sigue revisando el resultado antes de enviar nada**: la herramienta automatiza el trabajo pesado, no reemplaza el criterio.

## Qué hace

- **Une varios CSV** del mismo cliente aunque tengan columnas distintas entre sí, y detecta solo los nombres de columna (incluso con sufijos tipo `data.srcip: Descending` que agrega Kibana).
- **Deduplica**: una IP con 200 eventos se consulta una sola vez (suma los eventos, reglas, URLs y servidores atacados). Soporta exports agregados con columna `Count`.
- **Whitelist flexible**: IPs exactas, prefijos (`140.250.`) y rangos CIDR (`10.0.0.0/8`). Las IPs excluidas quedan visibles en el análisis pero no gastan cuota de la API.
- **Detecta IPs privadas** y las marca para revisar en vez de consultarlas.
- **Cache local** de consultas (2 días por defecto) para cuidar la cuota gratuita de AbuseIPDB (1.000 consultas por día).
- **Historial** de IPs vistas (90 días): avisa si una IP ya apareció en análisis anteriores, en qué clientes y con qué resultado.
- **Excel de salida** con la evidencia a la vista: veredicto con confidence y cantidad de reportes, servicio/ISP, antigüedad del último reporte y antecedentes. Las maliciosas salen primero y en rojo, más una hoja con las IPs a bloquear (una por fila).
- **Modo lista**: también analiza un `.txt` con IPs sueltas.

## Ejemplo de salida

Datos ilustrativos (no corresponden a un análisis real):

| IP | Pais | Analisis | Servicio (ISP) | Ultimo reporte | Antecedentes |
|---|---|---|---|---|---|
| 203.0.113.50 | Russia | Cuenta con registros maliciosos (100% - 847 reportes) | Example Hosting LLC | Reciente (hace 2 dias) | Ya registrada: 2 veces - ultima 15/09/2026 (maliciosa) - clientes: ClienteA, ClienteB |
| 198.51.100.77 | United States | Cuenta con registros maliciosos (88% - 210 reportes) | Example Networks Inc. | Antiguo (hace 6 meses) | Primera vez |
| 192.0.2.15 | Venezuela | No cuenta con registros maliciosos (0% - 0 reportes) | Example Telecom | - | Primera vez |

## Requisitos

- Python 3.10 o superior
- Una API key gratuita de AbuseIPDB (se genera en el perfil → pestaña API)
- Salida HTTPS hacia `api.abuseipdb.com`

## Instalación

```bash
git clone https://github.com/TU_USUARIO/analizador-ips.git
cd analizador-ips
pip install -r requirements.txt
```

Después, crear tus archivos de configuración a partir de las plantillas:

```bash
cp config.example.json config.json        # y pegar tu API key
cp whitelist.example.txt whitelist.txt    # y completar con tus IPs
```

En Windows, copiar y renombrar los archivos desde el Explorador. `config.json` y `whitelist.txt` están en `.gitignore`, así que nunca se suben al repositorio.

La API key también puede pasarse por variable de entorno (`ABUSEIPDB_API_KEY`).

## Uso

```bash
# Uno o varios exports de Wazuh
python analizador_ips.py --csv export1.csv export2.csv --cliente "Cliente A"

# Lista de IPs en un txt
python analizador_ips.py --txt lista_ips.txt --cliente "Consulta"

# Combinado, y con todas las columnas técnicas
python analizador_ips.py --csv export.csv --txt extras.txt --cliente "Cliente A" --detalle
```

En Windows se usa `py` en lugar de `python`. Hay archivos de ejemplo en [`examples/`](examples/).

| Opción | Descripción |
|---|---|
| `--csv` | Uno o más CSV exportados de Wazuh |
| `--txt` | Uno o más txt con una IP por línea |
| `--cliente` | Nombre del cliente (se usa en el nombre del archivo y en el historial) |
| `--detalle` | Agrega columnas técnicas: eventos, servidor atacado, reglas, URLs, whitelist, reportes, confidence, tipo de uso, tabla de origen |
| `--dias-cache N` | Días de validez del cache (por defecto 2) |
| `--salida ruta.xlsx` | Nombre o ruta personalizada del Excel |

Usar siempre el mismo nombre de cliente (mayúsculas y minúsculas incluidas), porque el historial lo guarda tal cual.

## Criterio de veredicto

Una IP se marca como **maliciosa** si tiene **2 o más reportes** en AbuseIPDB **o** un **confidence score de 25 o más**. Los umbrales están al inicio del script (`MIN_REPORTES_MALICIOSA` y `MIN_CONFIDENCE_MALICIOSA`).

Este criterio es deliberadamente simple y **sigue en calibración**: contar reportes crudos genera falsos positivos con IPs muy visibles (DNS públicos, scanners de investigación) que acumulan denuncias erróneas. Por eso el análisis muestra el confidence y la antigüedad del último reporte junto al veredicto, para que el analista pueda juzgar cada caso.

## Estructura del proyecto

```
analizador_ips.py          # el script
requirements.txt           # dependencias
config.example.json        # plantilla de configuración (API key)
whitelist.example.txt      # plantilla de whitelist
examples/                  # archivos de ejemplo para probar
```

Archivos que el script genera al ejecutarse (no se versionan): `cache_abuseipdb.json`, `historial_ips.json` y los reportes `reporte_<cliente>_<fecha>.xlsx`.

## Cómo funciona

1. Lee los CSV/txt y agrupa los eventos por IP única.
2. Filtra: whitelist y IPs privadas no se consultan.
3. Para el resto, usa el cache o consulta la API de AbuseIPDB (una vez por IP).
4. Aplica el criterio de veredicto, cruza con el historial y arma el Excel.

Librerías: `requests` (API), `pandas` (lectura y procesamiento de datos) y `openpyxl` (generación del Excel). Opcionalmente `truststore`, útil en redes corporativas cuyo firewall inspecciona el tráfico HTTPS: hace que Python valide contra el almacén de certificados del sistema.

## Limitaciones conocidas

- Una sola fuente de reputación (AbuseIPDB). La cuota gratuita es de 1.000 consultas por día.
- El historial es local: cada máquina tiene el suyo.
- Si se agota la cuota, las IPs restantes quedan como "Sin analizar" y el reporte se genera igual.
- Los nombres de columna reconocidos corresponden a exports de Wazuh/Kibana; otros formatos pueden requerir agregar sinónimos en las listas `COLUMNAS_*` del script.

## Ideas a futuro

- Consultar el Wazuh Indexer directamente, para eliminar el export manual de CSV.
- Sumar más fuentes de reputación y calibrar el veredicto con datos reales.
- Generar el borrador del ticket al cliente.

## Uso responsable

Herramienta pensada para análisis defensivo. Revisar los resultados antes de recomendar bloqueos y respetar los términos de uso de AbuseIPDB.
