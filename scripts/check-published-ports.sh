#!/usr/bin/env bash
# SecureFlow AI — P0-NET-01: published port policy.
#
# Reads what Docker actually has configured and bound (docker inspect, no output parsing) and
# fails unless every published port is on an explicit allow list and bound to 127.0.0.1.
#
# Usage:
#   check-published-ports.sh [--allow "<service> <port/proto> <host port>"]... <container>...
#   check-published-ports.sh [--allow ...] --records <file>     # evaluate saved records (tests)
#
# <service> is the Compose service label, or the container name if there is no label.
# Exit codes: 0 = compliant, 1 = violations (listed on stdout), 2 = could not evaluate.
# Anything that cannot be evaluated is an error, never a pass (fail closed).
set -uo pipefail

allow=()
records_file=""
while [ $# -gt 0 ]; do
  case "$1" in
    --allow)   allow+=("$2"); shift 2 ;;
    --records) records_file=$2; shift 2 ;;
    --)        shift; break ;;
    -*)        echo "unknown option: $1" >&2; exit 2 ;;
    *)         break ;;
  esac
done

# One MODE record per container, one BIND record per binding.
# "config" is what the container will use on every start (also covers stopped containers);
# "runtime" is what is bound right now.
FORMAT='MODE|{{.Name}}|{{index .Config.Labels "com.docker.compose.service"}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.PublishAllPorts}}
{{- $name := .Name}}{{$svc := index .Config.Labels "com.docker.compose.service"}}
{{- range $port, $binds := .HostConfig.PortBindings}}{{range $binds}}
BIND|{{$name}}|{{$svc}}|config|{{$port}}|{{.HostIp}}|{{.HostPort}}{{end}}{{end}}
{{- range $port, $binds := .NetworkSettings.Ports}}{{range $binds}}
BIND|{{$name}}|{{$svc}}|runtime|{{$port}}|{{.HostIp}}|{{.HostPort}}{{end}}{{end}}'

if [ -n "$records_file" ]; then
  records=$(cat "$records_file") || exit 2
else
  [ $# -gt 0 ] || { echo "no containers to check" >&2; exit 2; }
  records=$(docker inspect --format "$FORMAT" "$@") || { echo "docker inspect failed" >&2; exit 2; }
fi
[ -n "$records" ] || { echo "no records to check" >&2; exit 2; }

is_allowed() { # service port hostport
  local entry
  for entry in ${allow[@]+"${allow[@]}"}; do
    [ "$entry" = "$1 $2 $3" ] && return 0
  done
  return 1
}

violations=0
containers=0
bindings=0
report() { echo "VIOLATION: $1"; violations=$((violations+1)); }

while IFS='|' read -r kind name svc a b c d; do
  [ -n "$kind" ] || continue
  name=${name#/}
  [ "$svc" != "<no value>" ] || svc="" # docker's template output for a missing label
  svc=${svc:-$name}
  case "$kind" in
    MODE)
      containers=$((containers+1))
      [ "$a" = host ] && report "$svc: network mode 'host' exposes every listening port"
      [ "$b" = true ] && report "$svc: publish-all (-P) exposes ports on all interfaces"
      ;;
    BIND)
      bindings=$((bindings+1))
      where="$svc $b -> '$c':${d:-<ephemeral>} ($a)"
      case "$c" in
        "")        report "$where: all interfaces (no host address)" ;;
        0.0.0.0)   report "$where: all IPv4 interfaces" ;;
        ::|"[::]") report "$where: all IPv6 interfaces" ;;
        127.0.0.1) is_allowed "$svc" "$b" "$d" || report "$where: not on the allow list" ;;
        *)         report "$where: not bound to 127.0.0.1" ;;
      esac
      ;;
    *)
      echo "malformed record: $kind" >&2
      exit 2
      ;;
  esac
done <<< "$records"

[ "$containers" -gt 0 ] || { echo "no containers in the records" >&2; exit 2; }
if [ "$violations" -gt 0 ]; then
  echo "$violations violation(s) in $containers container(s)"
  exit 1
fi
echo "OK: $bindings binding(s) in $containers container(s) comply"
