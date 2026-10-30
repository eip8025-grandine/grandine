#!/usr/bin/env bash
# Runs design 0012's devnet recipe: builds the image, starts an enclave with
# one Grandine node, publishes the steps and evaluates them.
#
# Exits 0 (pass), 1 (a condition is contradicted) or 2 (inconclusive: setup,
# timeout or a change to B's eligibility). Needs Docker with BuildKit, the
# Kurtosis CLI and network access to build SP1.
#
# Usage: scripts/eip8025_devnet/run.sh [--keep]
#
# The evidence bundle goes to target/eip8025-devnet/<UTC timestamp>/. The
# enclave is removed unless --keep is given.
set -euo pipefail

readonly INCONCLUSIVE=2

# Any failure before the evaluation is a setup failure.
trap 'exit "$INCONCLUSIVE"' ERR

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)

keep=false

for argument in "$@"; do
    case "$argument" in
        --keep) keep=true ;;
        *)
            echo "usage: $0 [--keep]" >&2
            exit "$INCONCLUSIVE"
            ;;
    esac
done

# ethereum-package's latest release, 6.1.0, predates Glamsterdam devnet-8 and
# its genesis generator. This pins the main commit the recipe was written
# against. Override it with ETHEREUM_PACKAGE.
ethereum_package=${ETHEREUM_PACKAGE:-github.com/ethpandaops/ethereum-package@5795b77e65235ad223d4d3b413b2739190bf60cc}

readonly image=grandine-eip8025-devnet:local
readonly service=cl-1-grandine-geth
readonly beacon_port=4000

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
enclave=${ENCLAVE:-eip8025-${timestamp,,}}
bundle=$repo_root/target/eip8025-devnet/$timestamp
keys=$(mktemp -d)
log_follower=

mkdir -p "$bundle"

cleanup() {
    if [[ -n "$log_follower" ]]; then
        kill "$log_follower" 2>/dev/null || true
    fi

    rm -rf "$keys"

    if [[ "$keep" == true ]]; then
        echo "kept enclave $enclave" >&2
    else
        kurtosis enclave rm --force "$enclave" >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT

publisher() {
    docker run --rm --user "$(id -u):$(id -g)" --entrypoint execution_proof_publisher "$@"
}

# Parameters and versions.
cp "$script_dir/network_params.yaml" "$bundle/"

{
    echo "ethereum_package: $ethereum_package"
    echo "enclave: $enclave"
    echo "grandine_commit: $(git -C "$repo_root" rev-parse HEAD)"
    echo "grandine_dirty: $([[ -n "$(git -C "$repo_root" status --porcelain)" ]] && echo yes || echo no)"
    echo "eth2_libp2p_commit: $(git -C "$repo_root/eth2_libp2p" rev-parse HEAD)"
    echo "docker: $(docker version --format '{{.Server.Version}}')"
    echo "kurtosis: $(kurtosis version | sed -n 1p)"
} > "$bundle/versions.txt"

echo "building $image" >&2
DOCKER_BUILDKIT=1 docker build --file "$script_dir/Dockerfile" --tag "$image" "$repo_root" \
    > "$bundle/docker-build.log" 2>&1
echo "image_id: $(docker image inspect --format '{{.Id}}' "$image")" >> "$bundle/versions.txt"

echo "starting enclave $enclave" >&2
kurtosis run --enclave "$enclave" --image-download missing \
    "$ethereum_package" --args-file "$script_dir/network_params.yaml" \
    > "$bundle/kurtosis-run.log" 2>&1

# Kurtosis names a service's container `<service>--<UUID>` and attaches it to
# the enclave's `kt-` network, which the publisher joins.
container=$(docker ps --format '{{.Names}}' | grep -m 1 -E "^${service}--" || true)

if [[ -z "$container" ]]; then
    echo "no container for $service" >&2
    exit "$INCONCLUSIVE"
fi

network=$(
    docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' \
        "$container" | grep -m 1 -E '^kt-'
)
address=$(docker inspect --format "{{(index .NetworkSettings.Networks \"$network\").IPAddress}}" "$container")

# Grandine's log, streamed so the publisher can stop when B retires.
kurtosis service logs --all --follow "$enclave" "$service" > "$bundle/grandine.log" 2>&1 &
log_follower=$!

kurtosis files download "$enclave" el_cl_genesis_data "$bundle/network-configs" >/dev/null

keystore_artifact=$(kurtosis enclave inspect "$enclave" | grep -oE '[0-9]+-grandine-geth-[0-9]+-[0-9]+' | sed -n 1p)
kurtosis files download "$enclave" "$keystore_artifact" "$keys" >/dev/null

# The keystores keep Teku's layout, which ethereum-package hands to Grandine.
keystore_dir=$(find "$keys" -type d -name teku-keys -print -quit)
password_dir=$(find "$keys" -type d -name teku-secrets -print -quit)

if [[ -z "$keystore_artifact" || -z "$keystore_dir" || -z "$password_dir" ]]; then
    echo "no Grandine keystores in the enclave" >&2
    exit "$INCONCLUSIVE"
fi

echo "publishing to $address" >&2
publisher_status=0
publisher --network "$network" --volume "$bundle:/bundle" --volume "$keys:/keys:ro" "$image" run \
    --beacon-url "http://$address:$beacon_port" \
    --config /bundle/network-configs/config.yaml \
    --keystore-dir "/keys${keystore_dir#"$keys"}" \
    --password-dir "/keys${password_dir#"$keys"}" \
    --report /bundle/report.jsonl \
    --grandine-log /bundle/grandine.log \
    2> "$bundle/publisher.log" || publisher_status=$?
echo "publisher_exit: $publisher_status" >> "$bundle/versions.txt"

# Replace the streamed log with the complete one.
kill "$log_follower"
wait "$log_follower" 2>/dev/null || true
log_follower=
kurtosis service logs --all "$enclave" "$service" > "$bundle/grandine.log" 2>&1

# The evaluation sets the exit code, including for a run that stopped early.
trap - ERR
verdict_status=0
publisher --volume "$bundle:/bundle" "$image" evaluate \
    --report /bundle/report.jsonl \
    --log /bundle/grandine.log \
    --verdict /bundle/verdict.json \
    > "$bundle/verdict.md" || verdict_status=$?

cat "$bundle/verdict.md"
echo "evidence bundle: $bundle" >&2
exit "$verdict_status"
