#!/usr/bin/env bash
set -euo pipefail

pt --version
pt scan
pt robot plan --format summary
