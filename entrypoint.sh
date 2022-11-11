#!/usr/bin/env ash

# Deploy RSS-Syphon on Alpine

set -e
if [[ "${DEBUG}" == "yes" ]]; then
    set -o xtrace
else
    set +x
fi

python rss_syphon.py

exec "$@"
