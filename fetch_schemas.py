#!/usr/bin/env python3
"""
Fetch AWS CloudFormation resource schemas and extract resource identifiers.
Outputs a JSON file that can be used by the web page.
"""

import json
import zipfile
import io
import requests
from pathlib import Path


def fetch_schemas(region: str = "us-east-1") -> dict:
    """Fetch and parse AWS CloudFormation schemas for a given region."""
    url = f"https://schema.cloudformation.{region}.amazonaws.com/CloudformationSchema.zip"

    print(f"Downloading schemas from {url}...")
    response = requests.get(url)
    response.raise_for_status()

    print("Extracting and parsing schemas...")
    resources = []

    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
        for filename in zf.namelist():
            if filename.endswith('.json'):
                try:
                    schema = json.loads(zf.read(filename))
                    resource = extract_resource_info(schema)
                    if resource:
                        resources.append(resource)
                except (json.JSONDecodeError, KeyError) as e:
                    print(f"  Warning: Could not parse {filename}: {e}")

    print(f"Parsed {len(resources)} resources")
    return {"resources": sorted(resources, key=lambda x: x["typeName"])}


def extract_resource_info(schema: dict) -> dict | None:
    """Extract resource identifier information from a schema."""
    type_name = schema.get("typeName")
    if not type_name:
        return None

    # Parse type name into parts
    parts = type_name.split("::")
    if len(parts) != 3:
        return None

    provider, service, resource = parts

    # Get primary identifier
    primary_id = schema.get("primaryIdentifier", [])
    primary_id_props = [p.replace("/properties/", "") for p in primary_id]

    # Get additional identifiers
    additional_ids = schema.get("additionalIdentifiers", [])
    additional_id_props = [
        [p.replace("/properties/", "") for p in id_list]
        for id_list in additional_ids
    ]

    # Get read-only properties (often includes the identifier)
    read_only = schema.get("readOnlyProperties", [])
    read_only_props = [p.replace("/properties/", "") for p in read_only]

    # Get create-only properties
    create_only = schema.get("createOnlyProperties", [])
    create_only_props = [p.replace("/properties/", "") for p in create_only]

    # Get description
    description = schema.get("description", "")

    # Get properties definitions for identifier types
    properties = schema.get("properties", {})
    id_property_types = {}
    for prop in primary_id_props:
        if prop in properties:
            prop_def = properties[prop]
            id_property_types[prop] = prop_def.get("type", prop_def.get("$ref", "unknown"))

    return {
        "typeName": type_name,
        "provider": provider,
        "service": service,
        "resource": resource,
        "description": description[:200] if description else "",
        "primaryIdentifier": primary_id_props,
        "primaryIdentifierPath": primary_id,
        "additionalIdentifiers": additional_id_props,
        "readOnlyProperties": read_only_props,
        "createOnlyProperties": create_only_props,
        "identifierTypes": id_property_types,
    }


def main():
    output_file = Path(__file__).parent / "aws_resources.json"

    data = fetch_schemas("us-east-1")

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Saved {len(data['resources'])} resources to {output_file}")


if __name__ == "__main__":
    main()
