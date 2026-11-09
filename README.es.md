# f5-study: estudio de WAFs

Notas de campo y pequeñas herramientas del estudio de cómo tratan a un navegador las
capas WAF / anti-bot, con una capa F5 como primer caso. Reutilizable en otros proyectos;
no nombra ningún sitio, host ni operador. (El paquete conserva su nombre, `f5_study`.)

> Material educativo y de investigación defensiva. Úsalo solo en sistemas propios o con
> autorización para probarlos, y respeta los términos de cada servicio.

Versión en inglés: [README.md](README.md).

## Qué contiene

| Pieza | Qué es |
|---|---|
| `src/f5_study/chrome_cdp.py` | Chrome lanzado como lo haría un usuario (sin chromedriver ni flags de automatización) y manejado solo por CDP. Título leído de `/json` sin tocar la página; `evaluate()`, `cookies()`; Xvfb propio si no hay servidor X; cierre limpio con `Browser.close` |
| `Fingerprint`, `random_fingerprint()` | Varía zona horaria, idioma, WebGL y tamaño de ventana solo con flags y entorno |
| `src/f5_study/diagnose.py` (`f5-diagnose`) | Diagnóstico de una página: lanza el navegador, espera el reto, muestra la huella que ve la página y los **nombres** de las cookies, y da un veredicto |
| `src/f5_study/waf_block.py` | Neutral respecto al proveedor y puro: detección de bloqueo por cuerpo (`is_block_text`, `is_block_response`: 403/429 más un marcador; un 429 a secas no es bloqueo), estados de fallo rápido de un reto, clasificación `BLK-WAF` / `BLK-RATELIMIT` y `wait_until_settled` (vuelve antes con el motivo) |
| `src/f5_study/capture.py` | Diagnósticos que nunca lanzan excepción: `save_diagnostic` (captura + HTML) y `resource_statuses` (Performance API) |
| `docs/findings.md` | El estudio (en inglés): cómo se comportan las capas, qué falló, qué funcionó y por qué |

## Arranque rápido

```bash
pip install -e ".[test]"
pytest

f5-diagnose https://example.com/ --ready-marker "<app-root" --api-path /api/health
f5-diagnose https://example.com/ --fingerprint random --proxy 127.0.0.1:8899 --wait 60
```

## Resumen de hallazgos

1. Los clientes HTTP planos, incluso con impersonación TLS de navegador, acaban rechazados.
2. Lo que se vetaba era el Chrome del **framework de automatización**, no el binario.
3. Lo que se veta es la huella del dispositivo, no la IP: cambiar zona horaria, idioma y
   WebGL levantó un veto que cambiar de IP no levantaba.
4. Un bloqueo se decide por el cuerpo de la respuesta, nunca por el código (los rechazos
   llegan con HTTP 200).
5. Entre WAFs: el bloqueo puede quedar atado a la sesión (un perfil persistente lo
   arrastra), un 429 sin cabeceras de límite de tasa es un veredicto sobre el navegador y
   no un límite real, un user agent fijo que no cuadra con las Client Hints es una señal,
   un reto puede fallar rápido, la IP de salida se geolocaliza a través del proxy y todo
   resultado tiene fecha.

Esta herramienta detecta, clasifica y falla rápido; no derrota a un WAF.

Detalles y evidencias en [docs/findings.md](docs/findings.md).

## Licencia

MIT, ver [LICENSE](LICENSE).
