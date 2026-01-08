# Test Guide for Supra Views Proxy Server

## Prerequisites

1. Install dependencies:
```bash
npm install express
```

2. Set environment variables (optional):
```bash
export SUPRA_RPC_URL=https://rpc.supra.com
export VIEW_ALLOWLIST_FILE=./view_allowlist.json
export PORT=8787
```

## Start Server

```bash
node server.js
```

Expected output:
```
Server running on port 8787
Supra RPC URL: https://rpc.supra.com
Allowlist file: ./view_allowlist.json
Health check: http://localhost:8787/api/health
View endpoint: GET http://localhost:8787/api/view?fn=<FULL_FN>&args=<ARGS>
Batch endpoint: POST http://localhost:8787/api/view/batch
```

## Test Cases

### 1. Health Check
```bash
curl http://localhost:8787/api/health
```

Expected: `{"ok":true,"timestamp":"..."}`

### 2. Allowlist Debug Endpoint
```bash
curl http://localhost:8787/api/allowlist
```

Expected: `{"ok":true,"keys":["0xd1c64...::staking_v24","..."],"count":2,"function_counts":{...}}`

### 3. Allowed View Function (Single)
```bash
curl "http://localhost:8787/api/view?fn=0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3::staking_v24::total_staked"
```

Expected: `{"ok":true,"result":{...}}` (RPC response)

### 4. Disallowed Function (Should 403)
```bash
curl "http://localhost:8787/api/view?fn=0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3::staking_v24::stake_fa"
```

Expected: `{"ok":false,"error":"Function not allowed"}` with HTTP 403

### 5. Missing Function Parameter
```bash
curl "http://localhost:8787/api/view"
```

Expected: `{"ok":false,"error":"Missing required parameter: fn"}` with HTTP 400

### 6. Batch View Calls (2 Allowed)
```bash
curl -X POST http://localhost:8787/api/view/batch \
  -H "Content-Type: application/json" \
  -d '{
    "calls": [
      {"fn": "0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3::staking_v24::total_staked"},
      {"fn": "0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3::staking_v24::pool_stats"}
    ]
  }'
```

Expected: `{"ok":true,"results":[{"ok":true,"fn":"...","result":{...}},{"ok":true,"fn":"...","result":{...}}]}`

### 7. Batch with Mixed Allowed/Disallowed
```bash
curl -X POST http://localhost:8787/api/view/batch \
  -H "Content-Type: application/json" \
  -d '{
    "calls": [
      {"fn": "0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3::staking_v24::total_staked"},
      {"fn": "0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3::staking_v24::stake_fa"}
    ]
  }'
```

Expected: `{"ok":true,"results":[{"ok":true,"fn":"...","result":{...}},{"ok":false,"fn":"...","error":"Function not allowed"}]}`

### 8. Batch with Too Many Calls (Should Reject)
```bash
curl -X POST http://localhost:8787/api/view/batch \
  -H "Content-Type: application/json" \
  -d '{
    "calls": ['$(for i in {1..41}; do echo '{"fn":"0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3::staking_v24::total_staked"}'; done | tr '\n' ',' | sed 's/,$//')']
  }'
```

Expected: `{"ok":false,"error":"Maximum 40 calls allowed per batch"}` with HTTP 400

### 9. View Function with Arguments
```bash
curl "http://localhost:8787/api/view?fn=0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3::staking_v24::staked_of&args=0x123"
```

Expected: `{"ok":true,"result":{...}}` (RPC response with arguments)

## Notes

- All addresses in allowlist are lowercased for matching
- Function names are case-sensitive
- Allowlist is reloaded if file is modified (checked on each request)
- If allowlist file is missing or invalid, all requests are denied (safe default)
- Batch calls are processed sequentially to avoid overwhelming RPC

