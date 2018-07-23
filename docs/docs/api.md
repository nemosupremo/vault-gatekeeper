---
id: api
title: API Reference
---

Gatekeeper exposes a JSON HTTP API. The primary way of communicating with Gatekeeper is through the API.

## Standard Responses

The API will return a standard response for several the endpoints.

```json
{
	"unsealed": bool,
	"message": "string",
	"error": "string"
}
```

| Name | Type | Description |
| ---- | ---  | ----------- |
| `unsealed` | *boolean* | Seal status of the Gatekeeper instance. |
| `message` | *string* | If the request succeeded, this field may contain a message. |
| `error` | *string* | If an error occurred, this field will describe the error. |

###

## POST /token

Retrieve a response wrapped Vault token.

### Parameters

| Name | Type | Description |
| ---- | ---  | ----------- |
| `task_id` | *string*, **required** | The task ID, as reported to the service by the container scheduler. On Mesos, this will usually be in the environment variable `$MESOS_TASK_ID`. |
| `scheduler` | *string* | The scheduler that the task is scheduled on. If none is provided, Gatekeeper assumes the default. |
| `role` | *string* | The AppRole name requested by the task. If none is provided, Gatekeeper assigns the default for the task. |

### Response

#### JSON

A successful response will return a JSON object including the token.

| Name | Type | Description |
| ---- | ---  | ----------- |
| `token` | *string* | The response wrapped token ID. Use this token ID in the call to `sys/wrapping/unwrap` to retrieve the actual token. |
| `ttl` | *string* | The time-to-live on the response wrapped token. |
| `vault_addr` | *string* | The address to the vault server were the token was created. |

#### HTTP Status Code

| Code | Description |
| ---- | ----------- |
| 200  | The token was generated successfully. |
| 401  | The `task_id` provided, or the host requesting a token is not authorized to request tokens. |
| 403  | The request for a token is no longer valid, may be because the task has been running for too long. |
| 429  | The task has already been given its full allotment of tokens. Under normal conditions this may be considered a security error. If a service had expected to receive a token, and got this error, the token may have been stolen. |
| 500  | An internal server error occurred. |
| 503  | A token cannot be retrieved because the Gatekeeper is sealed. |

### Example

```python
import os
import json
import requests

r = requests.post("https://gatekeeper.internal:9201/token",
                  data=json.dumps({"task_id": os.environ['MESOS_TASK_ID']}))

if r.status_code == 200:
    t = r.json()['token']
    vault_addr = r.json()['vault_addr']
    r = requests.post(vault_addr + "v1/sys/wrapping/unwrap",
                      headers={"X-Vault-Token": t})
    if r.status_code == 200:
        print("Got the vault token: ", r.json()['auth']['client_token'])
    else:
        print("An error occurred: {}".format(r.text))
else:
    print("An error occurred: {}".format(r.text))
```

## GET /status

Get the status of the Gatekeeper instance.

### Response

#### JSON

| Name | Type | Description |
| ---- | ---- | ----------- |
| `id` | *string* | Peer ID of this instance. |
| `uptime` | *string* | The uptime of this instance. |
| `unsealed` | *bool* | Sealed status of this instance. |
| `started` | *timestamp* | The time this instance was started. |
| `version` | *string* | The version this instance is running. |
| `peers` | *list* | The list of peers, if running in high availability mode. |
| `peers[].id` | *string* | The id of the peer. |
| `peers[].address` | *string* | The address of the peer. |
| `peers[].unsealed` | *bool* | Sealed status of the peer. |
| `stats` | *object* | Various metrics for this instance. |
| `stats.requests` | `integer` | The number of token requests served by this instance. |
| `stats.successful` | `integer` | The number of token successful requests served by this instance. |
| `stats.denied` | `integer` | The number of token denied requests served by this instance. |
| `stats.failed` | `integer` | The number of token failed requests served by this instance. |

A denied request is one that Gatekeeper denied due to authorization policies. A failed request is one Gatekeeper was unable to serve due to any server issues.

#### HTTP Status Code

| Code | Description |
| ---- | ----------- |
| 200  | Gatekeeper is unsealed and serving requests. |
| 503  | Gatekeeper is sealed. |

## POST /seal

Seals the gatekeeper instance.

## POST /unseal

Unseal the gatekeeper instance.

### Parameters

| Name | Type | Description |
| ---- | ---  | ----------- |
| `method` | *string*, **required** | The method to use for unsealing. One of `token`, `token-wrapped`, `approle` or `aws`. |
| `token` | *string* | The token for `token` or `token-wrapped` authentication methods. |
| `role_id` | *string* | The `role_id` for the `approle` authentication method. |
| `secret_id` | *string* |  The `secret_id` for the `approle` authentication method. |
| `aws_role` | *string* | The AWS IAM role for the `aws` authentication method. |
| `aws_nonce` | *string* | The AWS nonce for the `aws` authentication method. |

### Response

#### HTTP Status Code

| Code | Description |
| ---- | ----------- |
| 200  | Gatekeeper was unsealed successfully. |
| 400  | There was a problem parsing the request. |
| 422  | The request could not be served - likely an invalid method. |
| 401  | Unsealing failed with the provided method. |
| 500  | An internal server error occurred. |

## POST /policies/reload

Reloads the policies from Vault into memory. If this instance is running in High Availability mode, it will also forward the reload command to any unsealed peers.