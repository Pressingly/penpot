#!/usr/bin/env bash

is_truthy() {
  local value="${1,,}"
  [[ "$value" == "true" || "$value" == "t" || "$value" == "1" ]]
}

is_falsy() {
  local value="${1,,}"
  [[ "$value" == "false" || "$value" == "f" || "$value" == "0" ]]
}


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

update_oidc_name() {
  if [ -n "$PENPOT_OIDC_NAME" ]; then
    echo "$(sed \
      -e "s|^//var penpotOIDCName = .*;|var penpotOIDCName = \"$PENPOT_OIDC_NAME\";|g" \
      "$1")" > "$1"
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
#
# Normalize: fold to lowercase, then validate against a strict whitelist of
# safe characters ([a-z0-9_-]).  Any value that contains special characters
# (spaces, #, &, \, ", newlines, …) is rejected and the line is left commented.
# The temp file is created in the same directory as the target so that the
# final 'mv' is always an atomic rename on the same filesystem (avoids EXDEV).
update_auth_type() {
  if [ -n "${AUTH_TYPE:-}" ]; then
    local auth_norm tmp
    auth_norm=$(printf '%s' "$AUTH_TYPE" | LC_ALL=C tr '[:upper:]' '[:lower:]')
    # Reject values that contain anything outside a-z 0-9 _ -
    if ! [[ "$auth_norm" =~ ^[a-z0-9_-]+$ ]]; then
      echo "update_auth_type: AUTH_TYPE contains invalid characters; skipping injection" >&2
      return 0
    fi
    tmp="$(mktemp -p "$(dirname "$1")")" || return 1
    if ! sed \
      -e "s#^//var penpotAuthType = .*;#var penpotAuthType = \"${auth_norm}\";#g" \
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
update_oidc_name /var/www/app/js/config.js
update_mpass_signout_url /var/www/app/js/config.js
update_auth_type /var/www/app/js/config.js

#########################################
## Nginx Config
#########################################

export PENPOT_BACKEND_URI=${PENPOT_BACKEND_URI:-http://penpot-backend:6060}
export PENPOT_EXPORTER_URI=${PENPOT_EXPORTER_URI:-http://penpot-exporter:6061}
export PENPOT_HTTP_SERVER_MAX_BODY_SIZE=${PENPOT_HTTP_SERVER_MAX_BODY_SIZE:-367001600} # Default to 350MiB
export PENPOT_IPV6_LISTEN_DIRECTIVE=${PENPOT_IPV6_LISTEN_DIRECTIVE:-"listen [::]:8080 default_server reuseport backlog=16384;"}
if is_truthy "${PENPOT_DISABLE_IPV6_LISTEN:-}"; then
  export PENPOT_IPV6_LISTEN_DIRECTIVE=""
fi
envsubst "\$PENPOT_BACKEND_URI,\$PENPOT_EXPORTER_URI,\$PENPOT_HTTP_SERVER_MAX_BODY_SIZE,\$PENPOT_IPV6_LISTEN_DIRECTIVE" \
        < /tmp/nginx.conf.template > /etc/nginx/nginx.conf

if [[ $PENPOT_FLAGS == *"enable-admin-console"* ]]; then
    export PENPOT_ADMIN_CONSOLE_URI=${PENPOT_ADMIN_CONSOLE_URI:-http://penpot-admin-console:3000}
    envsubst "\$PENPOT_ADMIN_CONSOLE_URI" \
             < /tmp/nginx-admin-console-locations.conf.template > /etc/nginx/overrides/server.d/admin-console-locations.conf
else
    rm -f /etc/nginx/overrides/server.d/admin-console-locations.conf
fi

if [[ $PENPOT_FLAGS == *"enable-mcp"* ]]; then
    export PENPOT_MCP_URI=${PENPOT_MCP_URI:-http://penpot-mcp:4401}
    export PENPOT_MCP_URI_WS=${PENPOT_MCP_URI_WS:-http://penpot-mcp:4402}

    envsubst "\$PENPOT_MCP_URI,\$PENPOT_MCP_URI_WS" \
             < /tmp/nginx-mcp-locations.conf.template > /etc/nginx/overrides/server.d/mcp-locations.conf
else
    rm -f /etc/nginx/overrides/server.d/mcp-locations.conf
fi

PENPOT_DEFAULT_INTERNAL_RESOLVER="$(awk 'BEGIN{ORS=" "} $1=="nameserver" { sub(/%.*$/,"",$2); print ($2 ~ ":")? "["$2"]": $2}' /etc/resolv.conf)"
export PENPOT_INTERNAL_RESOLVER=${PENPOT_INTERNAL_RESOLVER:-$PENPOT_DEFAULT_INTERNAL_RESOLVER}
envsubst "\$PENPOT_INTERNAL_RESOLVER" \
         < /tmp/resolvers.conf.template > /etc/nginx/overrides/http.d/resolvers.conf

exec "$@";
