#!/usr/bin/env bash
set -euo pipefail

pt --version
pt scan
pt agent plan --format summary
