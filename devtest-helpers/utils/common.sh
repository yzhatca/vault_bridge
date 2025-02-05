#!/bin/bash

# Function: Install required tools
install_required_tools() {
    echo "Checking required tools..."

    # Check and install Docker
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker is not installed. Installing..."
        sudo yum update -y
        sudo yum install -y docker
        sudo systemctl start docker
        sudo systemctl enable docker
    else
        echo "Docker is already installed."
    fi

    # Check and install Git
    if ! command -v git >/dev/null 2>&1; then
        echo "Git is not installed. Installing..."
        sudo yum install -y git
    else
        echo "Git is already installed."
    fi

    # Check and install Python
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Python3 is not installed. Installing..."
        sudo yum install -y python3 python3-pip
    else
        echo "Python3 is already installed."
    fi

    echo "All required tools are installed."
}

# Function: Generate a file from a template
generate_file_from_template() {
    local template_file=$1
    local output_dir=$2

    if [[ ! -f "$template_file" ]]; then
        echo "Template file $template_file does not exist."
        exit 1
    fi

    if [[ ! -d "$output_dir" ]]; then
        echo "Output directory $output_dir does not exist. Creating it..."
        mkdir -p "$output_dir"
    fi

    local output_file="${output_dir}/Dockerfile"
    echo "Generating file from template: $template_file -> $output_file"

    # Replace placeholders (adjust as per your template logic)
    sed -e "s/{{ bridgeutils.namespace }}/my-namespace/g" \
        -e "s/{{ bridgeutils.base_image }}/python/g" \
        -e "s/{{ bridgeutils.tag }}/3.11/g" \
        "$template_file" > "$output_file"
}

# Function: Report failure
report_failure() {
    local line_number=$1
    local exit_code=$2
    echo "Error at line $line_number: Exit code $exit_code"
    exit $exit_code
}
