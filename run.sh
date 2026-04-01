#!/usr/bin/fish

nvm use 22
ASTRO_TELEMETRY_DISABLED=1 npm run dev -- --host 127.0.0.1 --port 4321
