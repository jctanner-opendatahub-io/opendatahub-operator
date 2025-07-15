#!/usr/bin/env bash
set -e

# Check if we should skip manifest fetching (used in Docker builds when manifests are pre-populated)
if [[ "${SKIP_MANIFESTS_FETCH:-false}" == "true" ]]; then
    echo "SKIP_MANIFESTS_FETCH is set to true, skipping manifest fetching"
    exit 0
fi

# Prevent git from prompting for credentials - fail fast instead of hanging
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=""
export SSH_ASKPASS=""

GITHUB_URL="https://github.com"

# Fork, local checkout, and branch support
FORK_ORG=""
LOCAL_MODE=false
LOCAL_CHECKOUTS_DIR=""
BRANCH_NAME=""

# COMPONENT_MANIFESTS is a list of components repositories info to fetch the manifests
# in the format of "repo-org:repo-name:ref-name:source-folder" and key is the target folder under manifests/
declare -A COMPONENT_MANIFESTS=(
    ["dashboard"]="opendatahub-io:odh-dashboard:main:manifests"
    ["workbenches/kf-notebook-controller"]="opendatahub-io:kubeflow:main:components/notebook-controller/config"
    ["workbenches/odh-notebook-controller"]="opendatahub-io:kubeflow:main:components/odh-notebook-controller/config"
    ["workbenches/notebooks"]="opendatahub-io:notebooks:main:manifests"
    ["modelmeshserving"]="opendatahub-io:modelmesh-serving:release-0.12.0-rc0:config"
    ["kserve"]="opendatahub-io:kserve:release-v0.15:config"
    ["kueue"]="opendatahub-io:kueue:dev:config"
    ["codeflare"]="opendatahub-io:codeflare-operator:main:config"
    ["ray"]="opendatahub-io:kuberay:dev:ray-operator/config"
    ["trustyai"]="opendatahub-io:trustyai-service-operator:incubation:config"
    ["modelregistry"]="opendatahub-io:model-registry-operator:main:config"
    ["trainingoperator"]="opendatahub-io:training-operator:dev:manifests"
    ["datasciencepipelines"]="opendatahub-io:data-science-pipelines-operator:main:config"
    ["modelcontroller"]="opendatahub-io:odh-model-controller:incubating:config"
    ["feastoperator"]="opendatahub-io:feast:stable:infra/feast-operator/config"
    ["llamastackoperator"]="opendatahub-io:llama-stack-k8s-operator:odh:config"
)

# Allow overwriting repo using flags component=repo and new fork/local support
pattern="^[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+:[a-zA-Z0-9_./-]+$"
if [ "$#" -ge 1 ]; then
    for arg in "$@"; do
        if [[ $arg == --* ]]; then
            arg="${arg:2}"  # Remove the '--' prefix
            IFS="=" read -r key value <<< "$arg"
            
            # Handle special fork/local mode arguments
            case "$key" in
                "fork-org")
                    FORK_ORG="$value"
                    echo "Using fork organization: $FORK_ORG"
                    continue
                    ;;
                "local-mode")
                    LOCAL_MODE=true
                    echo "Local mode enabled"
                    continue
                    ;;
                "local-checkouts-dir")
                    LOCAL_CHECKOUTS_DIR="$value"
                    echo "Local checkouts directory: $LOCAL_CHECKOUTS_DIR"
                    continue
                    ;;
                "branch")
                    BRANCH_NAME="$value"
                    echo "Using feature branch: $BRANCH_NAME"
                    continue
                    ;;
            esac
            
            # Handle component overrides
            if [[ -n "${COMPONENT_MANIFESTS[$key]}" ]]; then
                if [[ ! $value =~ $pattern ]]; then
                    echo "ERROR: The value '$value' does not match the expected format 'repo-org:repo-name:ref-name:source-folder'."
                    continue
                fi
                COMPONENT_MANIFESTS["$key"]=$value
            else
                echo "ERROR: '$key' does not exist in COMPONENT_MANIFESTS, it will be skipped."
                echo "Available components are: [${!COMPONENT_MANIFESTS[@]}]"
                exit 1
            fi
        else
            echo "Warning: Argument '$arg' does not follow the '--key=value' format."
        fi
    done
fi

# Apply fork organization to all components if specified
if [[ -n "$FORK_ORG" ]]; then
    echo "Updating all component sources to use fork organization: $FORK_ORG"
    for key in "${!COMPONENT_MANIFESTS[@]}"; do
        repo_info="${COMPONENT_MANIFESTS[$key]}"
        # Replace opendatahub-io with fork org
        updated_repo_info="${repo_info/opendatahub-io:/$FORK_ORG:}"
        COMPONENT_MANIFESTS["$key"]="$updated_repo_info"
    done
fi

# Apply branch name to all components if specified
if [[ -n "$BRANCH_NAME" ]]; then
    echo "Updating all component sources to use branch: $BRANCH_NAME"
    for key in "${!COMPONENT_MANIFESTS[@]}"; do
        repo_info="${COMPONENT_MANIFESTS[$key]}"
        IFS=':' read -r -a parts <<< "$repo_info"
        # Replace the branch part (third element) with the specified branch
        # Format: repo-org:repo-name:ref-name:source-folder
        if [[ ${#parts[@]} -ge 3 ]]; then
            parts[2]="$BRANCH_NAME"
            updated_repo_info="${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}"
            COMPONENT_MANIFESTS["$key"]="$updated_repo_info"
        fi
    done
fi

TMP_DIR=$(mktemp -d -t "odh-manifests.XXXXXXXXXX")
trap '{ rm -rf -- "$TMP_DIR"; }' EXIT

function check_repo_exists()
{
    local repo_url=$1
    local repo_path
    
    # Extract org/repo from URL
    if [[ $repo_url == https://github.com/* ]]; then
        repo_path="${repo_url#https://github.com/}"
    else
        repo_path="$repo_url"
    fi
    
    # Use gh CLI to check if repo exists (faster and doesn't hang)
    if gh repo view "$repo_path" --json name >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

function git_fetch_ref()
{
    local repo=$1
    local ref=$2
    local dir=$3
    
    # Check if repo exists first
    if ! check_repo_exists "$repo"; then
        echo "ERROR: Repository $repo does not exist or is not accessible"
        return 1
    fi
    
    local git_fetch="git fetch -q --depth 1 $repo"

    mkdir -p $dir
    pushd $dir &>/dev/null
    git init -q
    # try tag first, avoid printing fatal: couldn't find remote ref
    if ! $git_fetch refs/tags/$ref 2>/dev/null ; then
        if ! $git_fetch refs/heads/$ref 2>/dev/null; then
            echo "ERROR: Failed to fetch ref $ref from $repo"
            popd &>/dev/null
            return 1
        fi
    fi
    git reset -q --hard FETCH_HEAD
    popd &>/dev/null
}

download_manifest() {
    local key=$1
    local repo_info=$2
    IFS=':' read -r -a repo_info <<< "${repo_info}"

    repo_org="${repo_info[0]}"
    repo_name="${repo_info[1]}"
    repo_ref="${repo_info[2]}"
    source_path="${repo_info[3]}"
    target_path="${key}"

    # Check for local checkout first if LOCAL_MODE is enabled
    if [[ "$LOCAL_MODE" == "true" && -n "$LOCAL_CHECKOUTS_DIR" ]]; then
        local_checkout_path="${LOCAL_CHECKOUTS_DIR}/${repo_name}"
        if [[ -d "$local_checkout_path" ]]; then
            echo -e "\033[32mUsing local checkout \033[33m${key}\033[32m:\033[0m ${local_checkout_path}"
            
            # Verify the source path exists in local checkout
            if [[ -d "${local_checkout_path}/${source_path}" ]]; then
                mkdir -p ./opt/manifests/${target_path}
                cp -rf "${local_checkout_path}/${source_path}"/* ./opt/manifests/${target_path}
                return 0
            else
                echo -e "\033[33mWarning: Source path '${source_path}' not found in local checkout, falling back to git clone\033[0m"
            fi
        else
            echo -e "\033[33mWarning: Local checkout not found at '${local_checkout_path}', falling back to git clone\033[0m"
        fi
    fi

    # Fall back to git clone (original behavior)
    echo -e "\033[32mCloning repo \033[33m${key}\033[32m:\033[0m ${repo_info}"
    
    repo_url="${GITHUB_URL}/${repo_org}/${repo_name}"
    repo_dir=${TMP_DIR}/${key}

    if git_fetch_ref ${repo_url} ${repo_ref} ${repo_dir}; then
        mkdir -p ./opt/manifests/${target_path}
        cp -rf ${repo_dir}/${source_path}/* ./opt/manifests/${target_path}
    else
        echo -e "\033[31mERROR: Failed to fetch manifests for ${key} from ${repo_url}\033[0m"
        echo -e "\033[33mSkipping component ${key} - you may need to:"
        # Show original repo name for forking suggestion
        original_repo="${repo_org/jctanner-opendatahub-io/opendatahub-io}"
        echo -e "  1. Fork ${original_repo}/${repo_name} to your organization"
        echo -e "  2. Create the ${repo_ref} branch in your fork"
        echo -e "  3. Or check if the repository exists\033[0m"
        return 1
    fi
}

# Track background job PIDs and component names
declare -a pids=()
declare -A pid_to_component=()

# Use parallel processing
for key in "${!COMPONENT_MANIFESTS[@]}"; do
    download_manifest "$key" "${COMPONENT_MANIFESTS[$key]}" &
    pid=$!
    pids+=($pid)
    pid_to_component[$pid]="$key"
done

# Wait and check exit codes with better error reporting
failed=0
failed_components=()
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
        failed=1
        failed_components+=("${pid_to_component[$pid]}")
    fi
done

if [ $failed -eq 1 ]; then
    echo -e "\033[31m===============================================\033[0m"
    echo -e "\033[31mSome manifest downloads failed:\033[0m"
    for component in "${failed_components[@]}"; do
        echo -e "\033[31m  - $component\033[0m"
    done
    echo -e "\033[33mThis usually means the fork repositories don't exist yet.\033[0m"
    echo -e "\033[33mRun 'python3 tool.py setup-forks' to create all required forks.\033[0m"
    echo -e "\033[31m===============================================\033[0m"
    exit 1
else
    echo -e "\033[32mAll manifests downloaded successfully!\033[0m"
fi
