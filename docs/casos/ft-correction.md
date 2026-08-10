# Caso — `ft-correction.com` (phishing Scotiabank Chile sobre sitio comprometido)

> Estado: **caso de estudio, cerrado como investigación activa** · Analizado 2026-07-15 · Separado
> del plan del honeypot el 2026-08-07.
> Era un caso real observado; se documenta por su valor de estudio, no como trabajo pendiente.
> Los "pendientes" del final quedan como ideas de pivoteo si alguna vez se retoma, no como tareas.

## Resumen (kill chain)

1. `ft-correction.com` = sitio legítimo de bajo perfil (Florence Tornatore, correctora FR;
   probable WordPress en VPS OVH).
2. Comprometido con el toolkit público de **InMyMine7** (`wp-upshell` / `Mephisto`): sube
   plugin/theme malicioso o inyecta en el plugin editor.
3. Se dropea el webshell **"Priv8 Uploader By InMyMine7"** (queda hasta en el index → owned total).
4. Un operador monta el phishing de Scotiabank Chile en subdir:
   `/actualizacion/reactivarscotiapassenlinea/SCOTIAPASSEMPRESASREACTIVA/`

> **Matiz de atribución:** la firma `InMyMine7` es del *autor de la herramienta* (repos GitHub
> públicos), NO del operador del phishing. El shell es reutilizable/descargable — no atribuye al
> phisher.

## IOCs

```
domain     ft-correction.com
ip         217.182.128.26  (AS16276 OVH SAS, FR; rDNS vps-8fd011e3.vps.ovh.net)
server     Apache/2.4.52 (Ubuntu), TLS Let's Encrypt (R12/R13)
url        /actualizacion/reactivarscotiapassenlinea/SCOTIAPASSEMPRESASREACTIVA/
webshell   "Priv8 Uploader By InMyMine7"  (prefijo GIF89a; / JFIF; campo form: backdoor_file; botón: upload)
markers    Sukses / Gagal Upload (indonesio); __halt_compiler() con payload embebido
actor_tool github.com/InMyMine7/*  (wp-upshell, Mephisto, Beelzebub, InMyMine-WebShell)
victim     Florence Tornatore (correctora FR) — su form de contacto ES el shell
reg/host   OVH SAS; creado 2023-09-09; expira 2026-09-09
```

## Reputación (a 2026-07-15)

- OTX: 26 pulses (PhishDestroy y clones), primer avistamiento ~feb-2026; un feed lo tagueó `opendir`.
- Pulsedive risk "none" (no probeado activamente, no concluyente).
- AbuseIPDB/GreyNoise/URLhaus/ThreatFox: sin reportes de IP ni URLs de payload catalogadas.
- urlscan: múltiples scans (16-abr-2026), título "Scotiabank - Portal Empresas".

## Firma de detección (YARA)

```yara
rule Webshell_InMyMine7_Priv8Uploader {
  strings:
    $m1 = "Priv8 Uploader By InMyMine7" nocase
    $m2 = "InMyMine7"
    $f  = "name='backdoor_file'" nocase
    $g  = "GIF89a;"
    $s  = "Gagal Upload"
  condition:
    $m1 or ($f and ($g or $s)) or ($m2 and $f)
}
```

Grep en servers propios: `grep -rl "backdoor_file\|InMyMine7\|Priv8 Uploader" /var/www`

## Ideas de pivoteo (si alguna vez se retoma)

- Pivots urlscan/VT por `page.title:"Priv8 Uploader"`, string `backdoor_file`, y la ruta
  `SCOTIAPASSEMPRESASREACTIVA` → sitios hermanos (mismo kit / mismo phishing-kit).
- Vecinos en `217.182.128.26` (otros vhosts en la misma VPS OVH).
- Perfilar toolmaker InMyMine7: repos, releases (variantes de firma), presencia Telegram.
- Notificar a la víctima; reportar a OVH abuse (abuse@ovh.net) con IOCs; CSIRT Scotiabank / CSIRT Chile.
- Sacar el código crudo de los shells del repo para YARA más finas (upload.php, upsx.php.txt).

## Valor para el lab

La regla YARA y el marco de dos poblaciones (mass-exploiters que *plantan* shells vs.
shell-finders que *parasitan* shells ajenos) salieron de este caso y siguen siendo la base
conceptual del honeypot. Ver el plan del honeypot en `honeypot/PLAN.md`.
