#!/usr/bin/env bash

#########################################
## Air Gapped config
#########################################

if [[ $PENPOT_FLAGS == *"enable-air-gapped-conf"* ]]; then
    rm /etc/nginx/overrides/location.d/external-locations.conf;
    export PENPOT_FLAGS="$PENPOT_FLAGS disable-google-fonts-provider disable-dashboard-templates-section"
fi

#########################################
## App Frontend config
#########################################

update_flags() {
  if [ -n "$PENPOT_FLAGS" ]; then
    echo "$(sed \
      -e "s|^//var penpotFlags = .*;|var penpotFlags = \"$PENPOT_FLAGS\";|g" \
      "$1")" > "$1"
  fi

  if [ -n "$PENPOT_PUBLIC_URI" ]; then
      echo "var penpotPublicURI = \"$PENPOT_PUBLIC_URI\";" >> "$1";
  fi
}

update_mpass_signout_url() {
  # Injected by foss-server-bundle-devstack for mPass SSO full-3-layer
  # logout. When MPASS_SIGNOUT_URL is set, the frontend logout button
  # redirects there instead of /auth/login — clearing the oauth2-proxy
  # cookie and the Cognito session in addition to the penpot session.
  if [ -n "$MPASS_SIGNOUT_URL" ]; then
    # `|` as sed delimiter because the URL contains `/` and `&`.
    echo "$(sed \
      -e "s|^//var penpotMpassSignoutUrl = .*;|var penpotMpassSignoutUrl = \"$MPASS_SIGNOUT_URL\";|g" \
      "$1")" > "$1"
  fi
}

# AUTH_TYPE (e.g. SSO): writes penpotAuthType into frontend config.js.
# Substitution uses '#' as the sed delimiter (values may include "/" or "|").
# Normalises AUTH_TYPE: strip control characters, trim whitespace, lowercase.
# Then escapes \, #, ", & before embedding into a JS double-quoted string.
# Writes via a temp file + mv so a failed/interrupted sed cannot truncate config.js.
update_auth_type() {
  if [ -n "${AUTH_TYPE:-}" ]; then
    local auth_norm auth_esc tmp
    # Strip control chars, trim leading/trailing whitespace, convert to lowercase.
    auth_norm=$(printf '%s' "$AUTH_TYPE" \
      | tr -d '[:cntrl:]' \
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
      | tr '[:upper:]' '[:lower:]')
    auth_esc=$(printf '%s' "$auth_norm" | sed \
      -e 's/\\/\\\\/g' \
      -e 's/#/\\#/g' \
      -e 's/&/\\\&/g' \
      -e 's/"/\\"/g')
    tmp="$(mktemp)" || return 1
    if ! sed \
      -e "s#^//var penpotAuthType = .*;#var penpotAuthType = \"${auth_esc}\";#g" \
      "$1" > "$tmp"; then
      rm -f "$tmp"
      return 1
    fi
    if ! mv "$tmp" "$1"; then
      rm -f "$tmp"
      return 1
    fi
  fi
}

update_flags /var/www/app/js/config.js
update_mpass_signout_url /var/www/app/js/config.js
update_auth_type /var/www/app/js/config.js

#########################################
## Nginx Config
#########################################

export PENPOT_BACKEND_URI=${PENPOT_BACKEND_URI:-http://penpot-backend:6060}
export PENPOT_EXPORTER_URI=${PENPOT_EXPORTER_URI:-http://penpot-exporter:6061}
export PENPOT_NITRATE_URI=${PENPOT_NITRATE_URI:-http://penpot-nitrate:3000}
export PENPOT_MCP_URI=${PENPOT_MCP_URI:-http://penpot-mcp:4401}
export PENPOT_MCP_URI_WS=${PENPOT_MCP_URI_WS:-http://penpot-mcp:4402}
export PENPOT_HTTP_SERVER_MAX_BODY_SIZE=${PENPOT_HTTP_SERVER_MAX_BODY_SIZE:-367001600} # Default to 350MiB
envsubst "\$PENPOT_BACKEND_URI,\$PENPOT_EXPORTER_URI,\$PENPOT_NITRATE_URI,\$PENPOT_MCP_URI,\$PENPOT_MCP_URI_WS,\$PENPOT_HTTP_SERVER_MAX_BODY_SIZE" \
         < /tmp/nginx.conf.template > /etc/nginx/nginx.conf

PENPOT_DEFAULT_INTERNAL_RESOLVER="$(awk 'BEGIN{ORS=" "} $1=="nameserver" { sub(/%.*$/,"",$2); print ($2 ~ ":")? "["$2"]": $2}' /etc/resolv.conf)"
export PENPOT_INTERNAL_RESOLVER=${PENPOT_INTERNAL_RESOLVER:-$PENPOT_DEFAULT_INTERNAL_RESOLVER}
envsubst "\$PENPOT_INTERNAL_RESOLVER" \
         < /tmp/resolvers.conf.template > /etc/nginx/overrides/http.d/resolvers.conf

exec "$@";
