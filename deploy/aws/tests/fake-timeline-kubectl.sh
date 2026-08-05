#!/usr/bin/env bash
set -euo pipefail

: "${FAKE_KUBECTL_STATE:?FAKE_KUBECTL_STATE is required}"
resource=""
selector=""
watch=0
namespace=""

while (( $# > 0 )); do
  case "$1" in
    --kubeconfig | --request-timeout | --output)
      shift 2
      ;;
    --request-timeout=* | --output=*)
      shift
      ;;
    --namespace)
      namespace=$2
      shift 2
      ;;
    --selector)
      selector=$2
      shift 2
      ;;
    --watch-only | --output-watch-events)
      watch=1
      shift
      ;;
    get)
      resource=$2
      shift 2
      ;;
    *)
      echo "fake kubectl received an unexpected argument: $1" >&2
      exit 64
      ;;
  esac
done

[[ "$namespace" == cats ]] || {
  echo "fake kubectl observed a namespace escape" >&2
  exit 65
}
case "$resource:$selector" in
  pods:app.kubernetes.io/name=cats-controld | endpointslices:kubernetes.io/service-name=cats-controld) ;;
  *)
    echo "fake kubectl observed an unscoped selector: $resource:$selector" >&2
    exit 65
    ;;
esac

mkdir -p "$FAKE_KUBECTL_STATE/live"
marker="$FAKE_KUBECTL_STATE/live/$BASHPID"
: >"$marker"
trap 'rm -f "$marker"' EXIT

pod_object() {
  local name=$1
  local uid=$2
  local resource_version=$3
  local pod_ip=$4
  local node=$5
  jq -cn \
    --arg name "$name" --arg uid "$uid" --arg rv "$resource_version" \
    --arg pod_ip "$pod_ip" --arg node "$node" '
    {
      metadata:{name:$name,uid:$uid,resourceVersion:$rv},
      spec:{
        nodeName:$node,
        containers:[{name:"controld",env:[{name:"SECRET",value:"MUST_NOT_ESCAPE"}]}]
      },
      status:{
        phase:"Running",podIP:$pod_ip,hostIP:"192.0.2.20",
        conditions:[{type:"Ready",status:"True",lastTransitionTime:"2026-08-05T17:00:00Z"}],
        containerStatuses:[{name:"controld",ready:true,restartCount:0,state:{running:{}}}]
      }
    }'
}

slice_object() {
  jq -cn '
    {
      metadata:{name:"cats-controld-fake",uid:"slice-uid",resourceVersion:"5"},
      addressType:"IPv4",
      endpoints:[
        {addresses:["192.0.2.11"],conditions:{ready:true,serving:true,terminating:false},targetRef:{name:"controld-a",uid:"uid-a"},nodeName:"node-a",zone:"zone-a"},
        {addresses:["192.0.2.12"],conditions:{ready:true,serving:true,terminating:false},targetRef:{name:"controld-b",uid:"uid-b"},nodeName:"node-b",zone:"zone-b"}
      ],
      ports:[{name:"http",port:7300}],
      forbidden:"MUST_NOT_ESCAPE"
    }'
}

if (( watch == 0 )); then
  case "$resource" in
    pods)
      first=$(pod_object controld-a uid-a 1 192.0.2.11 node-a)
      second=$(pod_object controld-b uid-b 2 192.0.2.12 node-b)
      jq -cn --argjson first "$first" --argjson second "$second" \
        '{apiVersion:"v1",kind:"PodList",items:[$first,$second]}'
      ;;
    endpointslices)
      slice=$(slice_object)
      jq -cn --argjson slice "$slice" \
        '{apiVersion:"discovery.k8s.io/v1",kind:"EndpointSliceList",items:[$slice]}'
      ;;
  esac
  exit 0
fi

case "$resource" in
  pods)
    object=$(pod_object controld-a uid-a 3 192.0.2.11 node-a)
    jq -cn --argjson object "$object" '{type:"MODIFIED",object:$object}'
    ;;
  endpointslices)
    object=$(slice_object)
    jq -cn --argjson object "$object" '{type:"MODIFIED",object:$object}'
    ;;
esac
sleep 60
