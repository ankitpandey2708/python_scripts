"""
Get API_KEY from https://web.postman.co/settings/me/api-keys


python postman_to_openapi.py --collection COLLECTION_ID --api-key API_KEY --out openapi.json

OR

python postman_to_openapi.py --collection COLLECTION_ID --api-key API_KEY --out openapi.yaml
"""
import argparse
import os
import sys
import json
import requests

POSTMAN_URL_TEMPLATE = "https://api.getpostman.com/collections/{collection_id}/transformations"
DEFAULT_OUTPUT_FILE = "my_openapi.json"

def get_transformations(collection_id: str, api_key: str, timeout: int = 30) -> dict:
    url = POSTMAN_URL_TEMPLATE.format(collection_id=collection_id)
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key
    }
    resp = requests.get(url, headers=headers, timeout=timeout)
    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        # Attempt to show helpful body if present
        msg = f"HTTP {resp.status_code} error while requesting Postman API: {e}"
        try:
            body = resp.json()
            msg += f"\nResponse JSON: {json.dumps(body, indent=2)}"
        except Exception:
            msg += f"\nResponse text: {resp.text[:1000]}"
        raise RuntimeError(msg) from e

    try:
        return resp.json()
    except ValueError as e:
        raise RuntimeError("Response was not valid JSON.") from e

def extract_openapi_object(transform_response: dict) -> dict:
    """
    The API response is expected to contain an 'output' field that itself is a JSON string.
    This function extracts that string and parses it into a Python dict.
    """
    if "output" not in transform_response:
        raise KeyError("Response JSON does not contain 'output' field.")
    output_raw = transform_response["output"]

    # output might already be a dict (if Postman changed their response shape), handle both cases:
    if isinstance(output_raw, dict):
        return output_raw

    if not isinstance(output_raw, str):
        raise TypeError(f"'output' field is unexpected type: {type(output_raw)}")

    try:
        # fromjson in jq means the field was a JSON string — parse it
        return json.loads(output_raw)
    except json.JSONDecodeError as e:
        # include a snippet for debugging
        snippet = output_raw[:1000]
        raise RuntimeError(f"Failed to parse 'output' JSON string. Snippet: {snippet!r}") from e

def save_json(obj: dict, path: str) -> None:
    """
    Saves the object as JSON by default. If the path ends with .yaml or .yml,
    attempts to write YAML instead.
    """
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml
        except Exception as e:
            raise RuntimeError("PyYAML is required to write YAML output. Install with `pip install pyyaml`.") from e
        with open(path, "w", encoding="utf-8") as f:
            # safe_dump with default_flow_style=False produces a readable YAML block style
            yaml.safe_dump(obj, f, sort_keys=False, allow_unicode=True)
        print(f"Saved OpenAPI YAML to: {path}")
        return

    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    print(f"Saved OpenAPI JSON to: {path}")

def main():
    parser = argparse.ArgumentParser(description="Fetch a Postman collection's OpenAPI transformation and save as JSON.")
    parser.add_argument("--collection", "-c", help="Postman collection ID (or set POSTMAN_COLLECTION_ID env var)")
    parser.add_argument("--api-key", "-k", help="Postman API key (or set POSTMAN_API_KEY env var)")
    parser.add_argument("--out", "-o", default=DEFAULT_OUTPUT_FILE, help=f"Output filename (default: {DEFAULT_OUTPUT_FILE})")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    args = parser.parse_args()

    collection_id = args.collection or os.environ.get("POSTMAN_COLLECTION_ID")
    api_key = args.api_key or os.environ.get("POSTMAN_API_KEY")
    out_file = args.out

    if not collection_id:
        print("Error: collection ID is required (use --collection or set POSTMAN_COLLECTION_ID).", file=sys.stderr)
        sys.exit(2)
    if not api_key:
        print("Error: API key is required (use --api-key or set POSTMAN_API_KEY).", file=sys.stderr)
        sys.exit(2)

    try:
        resp_json = get_transformations(collection_id, api_key, timeout=args.timeout)
        openapi_obj = extract_openapi_object(resp_json)
        save_json(openapi_obj, out_file)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

