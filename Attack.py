import json

def load_data(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

def get_technique_info(data, ttp_id):
    for technique in data.get("objects", []):  # Adjusted to handle nested structure
        if isinstance(technique, dict):
            external_refs = technique.get('external_references', [])
            for ref in external_refs:
                if ref.get('external_id') == ttp_id:
                    return technique["name"]
    return None

# Usage
file_path = 'enterprise-attack.json'  # Replace with the path to your dataset file
data = load_data(file_path)
ttp_id = 'T1071'  # Replace with the TTP ID you are interested in

technique_info = get_technique_info(data, ttp_id)
if technique_info:
    print(json.dumps(technique_info, indent=4))  # Pretty print the technique information
else:
    print(f"No technique found for TTP ID: {ttp_id}")
