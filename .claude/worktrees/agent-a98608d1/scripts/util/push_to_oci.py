import sys, urllib.request, hashlib, json, os

registry = sys.argv[1]
repo = sys.argv[2]
tag = sys.argv[3]
file_path = sys.argv[4]

with open(file_path, 'rb') as f:
    data = f.read()

layer_digest = "sha256:" + hashlib.sha256(data).hexdigest()
layer_size = len(data)

def do_request(url, method='GET', data=None, headers={}):
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return response, response.read()
    except urllib.error.HTTPError as e:
        return e, e.read()

# 1. Start upload for layer
resp, body = do_request(f"http://{registry}/v2/{repo}/blobs/uploads/", method='POST')
if resp.status not in (202, 201):
    print("Failed to start layer upload:", resp.status, body)
    sys.exit(1)

loc = resp.headers.get('Location')
if loc.startswith('/'):
    loc = f"http://{registry}" + loc

# 2. Upload layer blob
url = f"{loc}&digest={layer_digest}" if "?" in loc else f"{loc}?digest={layer_digest}"
resp, body = do_request(url, method='PUT', data=data, headers={'Content-Type': 'application/octet-stream'})
if resp.status != 201:
    print("Failed to upload layer:", resp.status, body)
    sys.exit(1)

# 3. Create config blob
config_data = b"{}"
config_digest = "sha256:" + hashlib.sha256(config_data).hexdigest()
config_size = len(config_data)

resp, body = do_request(f"http://{registry}/v2/{repo}/blobs/uploads/", method='POST')
loc = resp.headers.get('Location')
if loc.startswith('/'):
    loc = f"http://{registry}" + loc

url = f"{loc}&digest={config_digest}" if "?" in loc else f"{loc}?digest={config_digest}"
resp, body = do_request(url, method='PUT', data=config_data, headers={'Content-Type': 'application/octet-stream'})

# 4. Push manifest
manifest = {
    "schemaVersion": 2,
    "config": {
        "mediaType": "application/vnd.wasm.config.v1+json",
        "size": config_size,
        "digest": config_digest
    },
    "layers": [
        {
            "mediaType": "application/vnd.wasm.content.layer.v1+wasm",
            "size": layer_size,
            "digest": layer_digest
        }
    ]
}
manifest_json = json.dumps(manifest).encode('utf-8')
resp, body = do_request(
    f"http://{registry}/v2/{repo}/manifests/{tag}", 
    method='PUT', 
    data=manifest_json, 
    headers={'Content-Type': 'application/vnd.oci.image.manifest.v1+json'}
)
print(f"Pushed {repo}:{tag} -> Status {resp.status}")
