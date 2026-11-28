#!/usr/bin/env bash
# The mutation copy of the PHP SDK (run in sdks/php-pca): composer install, then Infection and the framework packages the Laravel
# service provider and the Symfony subscriber extend (Infection reflects every class it mutates: without them the process dies on
# "Class Illuminate\Support\ServiceProvider not found"). None of them is a dependency of the package: this CI copy only. The
# coverage job and every shard run this same script, so the coverage the shards share was measured over the same vendor tree.
set -euo pipefail
retry() {
  for n in 1 2 3 4; do
    "$@" && return 0
    [ "$n" = 4 ] && return 1
    echo "composer attempt $n failed (network); retrying"; sleep $((n * 15))
  done
}
retry composer install --prefer-dist --no-interaction --no-progress -q
composer config --no-interaction allow-plugins.infection/extension-installer true
retry composer require --dev --no-interaction --no-progress -q -W "infection/infection:^0.29" \
  "illuminate/support:>=10" "illuminate/http:>=10" "symfony/http-kernel:>=6.4" "symfony/psr-http-message-bridge:>=2.3"
python3 "$(dirname "$0")/infection-patch.py" vendor/infection/infection
