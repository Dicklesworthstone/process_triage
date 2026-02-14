#!/usr/bin/env bash
set -euo pipefail

pt robot plan --format toon --compact --max-tokens 800
pt agent plan --format json --fields minimal
pt agent plan --format summary --dry-run
