#!/bin/bash

# Function to fix YAML file formatting
fix_yaml_file() {
  local file=$1
  local temp_file="${file}.tmp"

  # Add document start marker and fix formatting
  {
    echo "---"
    # Skip any existing document start markers and process the rest of the file
    sed '/^---$/d' "$file" | awk '
      # Function to wrap long lines
      function wrap_line(line) {
        if (length(line) > 100) {
          # Find the last space before 100 characters
          split_pos = 100
          while (split_pos > 0 && substr(line, split_pos, 1) != " ") {
            split_pos--
          }
          if (split_pos > 0) {
            print substr(line, 1, split_pos)
            return "  " substr(line, split_pos + 1)
          }
        }
        return line
      }

      {
        # Process each line
        line = $0
        while (length(line) > 100) {
          line = wrap_line(line)
        }
        # Ensure proper indentation for block scalars
        if (line ~ /^[a-zA-Z_-]+:[ ]*[|>][ ]*$/) {
          print line
          next
        }
        print line
      }'
  } > "$temp_file"

  # Replace the original file
  mv "$temp_file" "$file"
}

# Create a template for agent YAML files
create_agent_template() {
  local file=$1
  local agent_name=$(basename $(dirname "$file") | tr '-' '_')

  cat > "$file" << EOF
---
# TEMPORARY PLACEHOLDER — TO BE REPLACED
#
# This is a temporary YAML structure for ${agent_name}.
# Replace with full agent definition including metadata, responsibilities, tools, steps, inputs,
# and outputs.

agent:
  name: "${agent_name}"
  uuid: "00000000-0000-0000-0000-000000000000"
  responsibilities: >-
    TODO: Define responsibilities for ${agent_name}.

system_prompt: |
  TODO: Provide a system prompt for this agent.

tools: []
external_knowledge: []
inputs: []
outputs: []
steps: []
EOF
}

# Fix all agent YAML files
for file in agents/*/agent.yaml; do
  echo "Fixing $file..."
  create_agent_template "$file"
done

# Fix workflow YAML files
for file in workflows/*.yaml; do
  echo "Fixing $file..."
  fix_yaml_file "$file"
done

# Fix GitHub workflow files
for file in .github/workflows/*.yml; do
  echo "Fixing $file..."
  fix_yaml_file "$file"
done

echo "YAML formatting complete!"
