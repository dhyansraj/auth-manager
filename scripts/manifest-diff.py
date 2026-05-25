#!/usr/bin/env python3
"""
manifest-diff.py — Compare a tenant's live Keycloak state (exported via
auth-manager) against a local manifest YAML and report drift.

Foundation for the manifest schema-expansion work (auth-platform backlog #54).

Usage:
    scripts/manifest-diff.py <tenant-slug> <path/to/manifest.yaml>
    scripts/manifest-diff.py --json <tenant-slug> <path/to/manifest.yaml>

Env (all optional):
    AUTH_MGR_BASE  default https://auth.mcp-mesh.io
    KC_BASE        default https://auth.mcp-mesh.io/auth
    KC_REALM       default dev
    KC_CLIENT_ID   default admin-cli
    KC_USERNAME    default admin
    KC_PASSWORD    default admin

Exit codes:
    0  clean (manifest matches KC)
    1  drift detected
    2  configuration / network / parse error
"""

import argparse
import json
import os
import sys

try:
    import requests
except ImportError:
    print("error: 'requests' is required. Run: pip install requests PyYAML", file=sys.stderr)
    sys.exit(2)

try:
    import yaml
except ImportError:
    print("error: 'PyYAML' is required. Run: pip install requests PyYAML", file=sys.stderr)
    sys.exit(2)


# ─── Auth ────────────────────────────────────────────────────────────────

def mint_jwt() -> str:
    """Mint a JWT via KC password grant. Exits 2 on failure."""
    kc_base     = os.environ.get("KC_BASE",      "https://auth.mcp-mesh.io/auth")
    kc_realm    = os.environ.get("KC_REALM",     "dev")
    kc_client   = os.environ.get("KC_CLIENT_ID", "admin-cli")
    kc_user     = os.environ.get("KC_USERNAME",  "admin")
    kc_password = os.environ.get("KC_PASSWORD",  "admin")

    token_url = f"{kc_base.rstrip('/')}/realms/{kc_realm}/protocol/openid-connect/token"
    try:
        r = requests.post(
            token_url,
            data={
                "grant_type": "password",
                "client_id":  kc_client,
                "username":   kc_user,
                "password":   kc_password,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
    except requests.RequestException as e:
        print(
            f"error: could not reach KC at {token_url}: {e}\n"
            f"check env vars KC_BASE, KC_REALM, KC_CLIENT_ID, KC_USERNAME, KC_PASSWORD",
            file=sys.stderr,
        )
        sys.exit(2)

    if r.status_code != 200:
        print(
            f"error: KC token request failed ({r.status_code}): {r.text[:300]}\n"
            f"check env vars KC_BASE, KC_REALM, KC_CLIENT_ID, KC_USERNAME, KC_PASSWORD",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        return r.json()["access_token"]
    except (ValueError, KeyError) as e:
        print(f"error: KC token response missing access_token: {e}", file=sys.stderr)
        sys.exit(2)


# ─── Fetch + load ────────────────────────────────────────────────────────

def fetch_kc_manifest(jwt: str, slug: str) -> dict:
    base = os.environ.get("AUTH_MGR_BASE", "https://auth.mcp-mesh.io").rstrip("/")
    url  = f"{base}/api/v1/tenants/{slug}/manifest"
    try:
        r = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {jwt}",
                "Accept":        "application/yaml",
            },
            timeout=30,
        )
    except requests.RequestException as e:
        print(f"error: could not reach auth-manager at {url}: {e}", file=sys.stderr)
        sys.exit(2)

    if r.status_code != 200:
        print(
            f"error: manifest export failed ({r.status_code}) for tenant '{slug}': "
            f"{r.text[:300]}",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        return yaml.safe_load(r.text) or {}
    except yaml.YAMLError as e:
        print(f"error: failed to parse KC manifest YAML: {e}", file=sys.stderr)
        sys.exit(2)


def load_local_manifest(path: str) -> dict:
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"error: local manifest not found: {path}", file=sys.stderr)
        sys.exit(2)
    except yaml.YAMLError as e:
        print(f"error: failed to parse local manifest YAML ({path}): {e}", file=sys.stderr)
        sys.exit(2)


# ─── Normalization ───────────────────────────────────────────────────────

def _norm_desc(d):
    """null / missing / empty-string description all collapse to None."""
    if d is None:
        return None
    if isinstance(d, str) and d.strip() == "":
        return None
    return d


def _norm_perm(p: dict) -> dict:
    return {
        "id":          p.get("id"),
        "description": _norm_desc(p.get("description")),
        "client":      p.get("client"),
    }


def _norm_role(r: dict) -> dict:
    perms = r.get("permissions") or []  # null -> []
    return {
        "name":        r.get("name"),
        "description": _norm_desc(r.get("description")),
        "permissions": sorted(perms),
    }


def _norm_idp(i: dict) -> dict:
    """Missing `enabled` defaults to True, matching Java apply semantics."""
    enabled = i.get("enabled")
    if enabled is None:
        enabled = True
    return {
        "id":      i.get("id"),
        "enabled": bool(enabled),
    }


def normalize(manifest: dict) -> dict:
    """Drop `meta`, sort lists, sort nested perms, normalize descriptions.

    Also tracks presence of the v2 sections (identityProviders / defaultRoles)
    so the success line can omit them when both sides predate the schema bump.
    """
    perms = manifest.get("permissions") or []
    roles = manifest.get("roles")       or []
    idps  = manifest.get("identityProviders") or []
    droles = manifest.get("defaultRoles") or []

    perms_n = sorted((_norm_perm(p) for p in perms), key=lambda x: (x.get("id") or ""))
    roles_n = sorted((_norm_role(r) for r in roles), key=lambda x: (x.get("name") or ""))
    idps_n  = sorted((_norm_idp(i) for i in idps),   key=lambda x: (x.get("id") or ""))
    droles_n = sorted(str(r) for r in droles)

    return {
        "permissions":          perms_n,
        "roles":                roles_n,
        "identityProviders":    idps_n,
        "defaultRoles":         droles_n,
        "_has_idps":            "identityProviders" in manifest,
        "_has_default_roles":   "defaultRoles" in manifest,
    }


# ─── Diff ────────────────────────────────────────────────────────────────

def diff_permissions(local: list, kc: list) -> dict:
    by_id_local = {p["id"]: p for p in local}
    by_id_kc    = {p["id"]: p for p in kc}

    only_local = sorted(set(by_id_local) - set(by_id_kc))
    only_kc    = sorted(set(by_id_kc)    - set(by_id_local))

    field_diffs = []
    for pid in sorted(set(by_id_local) & set(by_id_kc)):
        l = by_id_local[pid]
        k = by_id_kc[pid]
        if l != k:
            field_diffs.append({"id": pid, "local": l, "kc": k})

    return {
        "only_in_local": only_local,
        "only_in_kc":    only_kc,
        "field_diffs":   field_diffs,
    }


def diff_roles(local: list, kc: list) -> dict:
    by_name_local = {r["name"]: r for r in local}
    by_name_kc    = {r["name"]: r for r in kc}

    only_local = sorted(set(by_name_local) - set(by_name_kc))
    only_kc    = sorted(set(by_name_kc)    - set(by_name_local))

    member_diffs = []
    for name in sorted(set(by_name_local) & set(by_name_kc)):
        l = by_name_local[name]
        k = by_name_kc[name]
        l_perms = set(l["permissions"])
        k_perms = set(k["permissions"])
        only_in_local = sorted(l_perms - k_perms)
        only_in_kc    = sorted(k_perms - l_perms)
        desc_differs  = l["description"] != k["description"]
        if only_in_local or only_in_kc or desc_differs:
            member_diffs.append({
                "name":                name,
                "only_in_local":       only_in_local,
                "only_in_kc":          only_in_kc,
                "description_differs": desc_differs,
            })

    return {
        "only_in_local": only_local,
        "only_in_kc":    only_kc,
        "member_diffs":  member_diffs,
    }


def diff_identity_providers(local: list, kc: list) -> dict:
    by_id_local = {i["id"]: i for i in local}
    by_id_kc    = {i["id"]: i for i in kc}

    only_local = sorted(set(by_id_local) - set(by_id_kc))
    only_kc    = sorted(set(by_id_kc)    - set(by_id_local))

    field_diffs = []
    for iid in sorted(set(by_id_local) & set(by_id_kc)):
        l = by_id_local[iid]
        k = by_id_kc[iid]
        if l != k:
            field_diffs.append({"id": iid, "local": l, "kc": k})

    return {
        "only_in_local": only_local,
        "only_in_kc":    only_kc,
        "field_diffs":   field_diffs,
    }


def diff_default_roles(local: list, kc: list) -> dict:
    only_local = sorted(set(local) - set(kc))
    only_kc    = sorted(set(kc)    - set(local))
    return {
        "only_in_local": only_local,
        "only_in_kc":    only_kc,
    }


def section_has_drift(section: dict, *, kind: str) -> bool:
    if section["only_in_local"] or section["only_in_kc"]:
        return True
    if kind == "permissions":
        return bool(section["field_diffs"])
    if kind == "roles":
        return bool(section["member_diffs"])
    if kind == "identityProviders":
        return bool(section["field_diffs"])
    # defaultRoles: only the set-difference counts
    return False


# ─── Output ──────────────────────────────────────────────────────────────

def print_text(slug: str, sections: dict, local_norm: dict, kc_norm: dict) -> int:
    perms_drift  = section_has_drift(sections["permissions"],       kind="permissions")
    roles_drift  = section_has_drift(sections["roles"],             kind="roles")
    idps_drift   = section_has_drift(sections["identityProviders"], kind="identityProviders")
    droles_drift = section_has_drift(sections["defaultRoles"],      kind="defaultRoles")
    drift_count  = (int(perms_drift) + int(roles_drift)
                    + int(idps_drift) + int(droles_drift))

    show_idps   = (local_norm["_has_idps"]
                   or kc_norm["_has_idps"]
                   or bool(local_norm["identityProviders"])
                   or bool(kc_norm["identityProviders"]))
    show_droles = (local_norm["_has_default_roles"]
                   or kc_norm["_has_default_roles"]
                   or bool(local_norm["defaultRoles"])
                   or bool(kc_norm["defaultRoles"]))

    if drift_count == 0:
        n_perms  = len(local_norm["permissions"])
        n_roles  = len(local_norm["roles"])
        parts    = [f"{n_perms} perms", f"{n_roles} roles"]
        if show_idps:
            n_idps = len(local_norm["identityProviders"])
            parts.append(f"{n_idps} IdPs")
        if show_droles:
            n_dr = len(local_norm["defaultRoles"])
            parts.append(f"{n_dr} default role{'s' if n_dr != 1 else ''}")
        print(
            f"Manifest matches KC state for tenant '{slug}' "
            f"({', '.join(parts)}). exit 0"
        )
        return 0

    if perms_drift:
        s = sections["permissions"]
        print("=== permissions ===")
        print(f"only in LOCAL:  {s['only_in_local']}")
        print(f"only in KC:     {s['only_in_kc']}")
        if s["field_diffs"]:
            print("field diffs:")
            for fd in s["field_diffs"]:
                # show only fields that differ for readability
                l_short = {k: v for k, v in fd["local"].items() if k != "id"}
                k_short = {k: v for k, v in fd["kc"].items()    if k != "id"}
                print(f"  {fd['id']}:")
                print(f"    local:    {l_short}")
                print(f"    KC:       {k_short}")

    if roles_drift:
        s = sections["roles"]
        print("=== roles ===")
        print(f"only in LOCAL:  {s['only_in_local']}")
        print(f"only in KC:     {s['only_in_kc']}")
        if s["member_diffs"]:
            print("role member diffs:")
            for md in s["member_diffs"]:
                print(f"  {md['name']}:")
                print(f"    only-in-local:  {md['only_in_local']}")
                print(f"    only-in-KC:     {md['only_in_kc']}")
                print(f"    description differs: {str(md['description_differs']).lower()}")

    if idps_drift:
        s = sections["identityProviders"]
        print("=== identityProviders ===")
        print(f"only in LOCAL:  {s['only_in_local']}")
        print(f"only in KC:     {s['only_in_kc']}")
        if s["field_diffs"]:
            print("field diffs:")
            for fd in s["field_diffs"]:
                l_short = {k: v for k, v in fd["local"].items() if k != "id"}
                k_short = {k: v for k, v in fd["kc"].items()    if k != "id"}
                print(f"  {fd['id']}:")
                print(f"    local:  {l_short}")
                print(f"    KC:     {k_short}")

    if droles_drift:
        s = sections["defaultRoles"]
        print("=== defaultRoles ===")
        print(f"only in LOCAL:  {s['only_in_local']}")
        print(f"only in KC:     {s['only_in_kc']}")

    print(f"\nResult: DRIFT in {drift_count} section(s) — exit 1")
    return 1


def print_json(slug: str, sections: dict, local_norm: dict, kc_norm: dict) -> int:
    perms_drift  = section_has_drift(sections["permissions"],       kind="permissions")
    roles_drift  = section_has_drift(sections["roles"],             kind="roles")
    idps_drift   = section_has_drift(sections["identityProviders"], kind="identityProviders")
    droles_drift = section_has_drift(sections["defaultRoles"],      kind="defaultRoles")
    clean = not (perms_drift or roles_drift or idps_drift or droles_drift)

    # Keep payload lean for clients still on v1 schema: omit the new section
    # keys when neither side has them and neither has drift in them.
    out_sections = {
        "permissions": sections["permissions"],
        "roles":       sections["roles"],
    }
    show_idps   = (local_norm["_has_idps"]
                   or kc_norm["_has_idps"]
                   or bool(local_norm["identityProviders"])
                   or bool(kc_norm["identityProviders"]))
    show_droles = (local_norm["_has_default_roles"]
                   or kc_norm["_has_default_roles"]
                   or bool(local_norm["defaultRoles"])
                   or bool(kc_norm["defaultRoles"]))
    if show_idps:
        out_sections["identityProviders"] = sections["identityProviders"]
    if show_droles:
        out_sections["defaultRoles"] = sections["defaultRoles"]

    payload = {
        "tenant":   slug,
        "clean":    clean,
        "sections": out_sections,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if clean else 1


# ─── Main ────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Diff a tenant's KC state against a local manifest YAML."
    )
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("tenant", help="tenant slug (e.g. safesound)")
    ap.add_argument("manifest", help="path to local manifest YAML")
    args = ap.parse_args()

    jwt        = mint_jwt()
    kc_raw     = fetch_kc_manifest(jwt, args.tenant)
    local_raw  = load_local_manifest(args.manifest)

    kc_norm    = normalize(kc_raw)
    local_norm = normalize(local_raw)

    sections = {
        "permissions":       diff_permissions(local_norm["permissions"], kc_norm["permissions"]),
        "roles":             diff_roles(      local_norm["roles"],       kc_norm["roles"]),
        "identityProviders": diff_identity_providers(
            local_norm["identityProviders"], kc_norm["identityProviders"]),
        "defaultRoles":      diff_default_roles(
            local_norm["defaultRoles"],      kc_norm["defaultRoles"]),
    }

    if args.json:
        return print_json(args.tenant, sections, local_norm, kc_norm)
    return print_text(args.tenant, sections, local_norm, kc_norm)


if __name__ == "__main__":
    sys.exit(main())
