#!/bin/sh

set -eu

client_id=
client_secret=

if [ -z "$client_id" -o -z "$client_secret" ]; then
 echo "please edit the client_id and client_secret in run.sh" >&2
 exit 1
fi

export ROCKET_OAUTH='{ github = {
  auth_uri = "https://github.com/login/oauth/authorize",
  token_uri = "https://github.com/login/oauth/access_token",
  client_id = "'"$client_id"'",
  client_secret = "'"$client_secret"'",
  redirect_uri = "http://localhost:8000/auth/github"
} }'

echo $ROCKET_OAUTH

cargo run "$@"
