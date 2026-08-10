#!/bin/bash
# publicar-informes.sh — deja los informes terminados en el share que sirve copyparty.
#
# Se instala en el CT 113 como /usr/local/bin/publicar-informes.sh y corre como
# ExecStartPost=- de separatio.service y separatio-weekly.service (con guión: que
# fallar la copia NO marque la corrida como fallida, invariante 1 del rework).
#
#   host   /mnt/pve/nvme-data/cloud/Intel   →  CT 113 /mnt/informes  (mp0)
#                                           →  CT 104 /media/storage/Intel (copyparty)
#
# El directorio de trabajo del pipeline sigue siendo local: acá sólo se copia el
# producto final, así que ni los dry-run, ni el caché de resúmenes, ni los
# run-manifest.json ensucian el share.
#
# Ojo con dónde cae cada cosa, que no es obvio (reporter.py): el .md y el .html
# van a <fecha>/reports/, pero el **PDF va a <fecha>/** a secas. Se buscan los
# dos sitios; buscar sólo en reports/ fue el primer bug de este script.
#
# Idempotente a propósito (`cp -u`): el pipeline corre a diario y esto se puede
# relanzar a mano sin duplicar nada.

set -u

ORIGEN=/opt/intel/app/separatio/reports
DESTINO=/mnt/informes

if [ ! -d "$DESTINO" ]; then
    echo "[publicar] $DESTINO no está montado — no se publica nada"
    exit 0
fi

publicados=0
for dir in "$ORIGEN"/*/; do
    fecha=$(basename "$dir")
    # Sólo carpetas con nombre de fecha: así `dryrun/` queda afuera por
    # construcción y no por una lista de exclusiones que se pudra.
    [[ "$fecha" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || continue

    mkdir -p "$DESTINO/$fecha" || continue
    for f in "$dir"reports/*.pdf "$dir"reports/*.html "$dir"*.pdf; do
        [ -e "$f" ] || continue
        if cp -u "$f" "$DESTINO/$fecha/"; then
            publicados=$((publicados + 1))
        fi
    done
done

echo "[publicar] $publicados fichero(s) al día en $DESTINO"
