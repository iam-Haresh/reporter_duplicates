"""
GitLab Enterprise — Reporter Role Conflict Finder

Finds active LDAP users who are a Reporter in one group and also hold a
different role in another group. Writes a CSV report.

Usage:
    GITLAB_URL=https://gitlab.example.com GITLAB_TOKEN=glpat-xxx python gitlab_reporter_check.py
    (or put GITLAB_URL / GITLAB_TOKEN in a .env file)
"""

import csv
import os
import sys
from datetime import datetime

import gitlab
from dotenv import load_dotenv

# Standard GitLab roles by access level, plus this instance's custom roles.
ROLE_NAMES = {10: "Guest", 20: "Reporter", 30: "Developer", 40: "Maintainer", 50: "Owner"}
CUSTOM_ROLES = {3: "appsec-vuln-approver", 4: "Application_Owner"}
REPORTER_LEVEL = 20

CSV_COLUMNS = [
    "username", "user_display_name", "user_email", "ldap_provider",
    "reporter_top_level_group", "reporter_group_path", "reporter_group_ldap_linked",
    "other_top_level_group", "other_group_path", "other_group_ldap_linked",
    "other_role_name", "other_access_level", "other_member_role_id",
]


def role_name(access_level, member_role_id):
    """Human-readable role: custom role takes precedence over the standard one."""
    if member_role_id:
        return CUSTOM_ROLES.get(member_role_id, f"custom_role_{member_role_id}")
    return ROLE_NAMES.get(access_level, str(access_level))


def is_ldap_user(gl, user_id, cache):
    """Return the LDAP provider name if the user has an LDAP identity, else ''. Cached."""
    if user_id not in cache:
        user = gl.users.get(user_id)
        provider = next(
            (i["provider"] for i in user.identities if i.get("provider", "").startswith("ldap")),
            "",
        )
        cache[user_id] = (user, provider)
    return cache[user_id][1]


def main():
    load_dotenv()
    url = os.environ.get("GITLAB_URL", "").strip()
    token = os.environ.get("GITLAB_TOKEN", "").strip()
    if not url or not token:
        sys.exit("Error: GITLAB_URL and GITLAB_TOKEN must be set (env var or .env file).")

    gl = gitlab.Gitlab(url=url, private_token=token)

    print(f"Connecting to {url} ...")
    groups = gl.groups.list(all=True)  # includes every subgroup as its own group
    print(f"Found {len(groups)} groups (including subgroups).\n")

    user_cache = {}                  # user_id -> (user_obj, ldap_provider)
    memberships = {}                 # user_id -> list of membership dicts

    for idx, g in enumerate(groups, 1):
        top_level = g.full_path.split("/")[0]
        ldap_linked = bool(g.ldap_group_links.list())
        print(f"[{idx}/{len(groups)}] {g.full_path}")

        for m in g.members.list(all=True):          # direct members only
            if m.state != "active":                 # skip blocked / inactive
                continue
            provider = is_ldap_user(gl, m.id, user_cache)
            if not provider:                         # LDAP users only
                continue

            memberships.setdefault(m.id, []).append({
                "top_level": top_level,
                "group_path": g.full_path,
                "ldap_linked": ldap_linked,
                "access_level": m.access_level,
                "member_role_id": getattr(m, "member_role_id", None),
                "provider": provider,
            })

    # Flag users who are a plain Reporter somewhere AND hold another role elsewhere.
    rows = []
    for user_id, records in memberships.items():
        reporters = [r for r in records if r["access_level"] == REPORTER_LEVEL and not r["member_role_id"]]
        others = [r for r in records if not (r["access_level"] == REPORTER_LEVEL and not r["member_role_id"])]
        if not reporters or not others:
            continue

        user = user_cache[user_id][0]
        for rep in reporters:
            for other in others:
                rows.append({
                    "username": user.username,
                    "user_display_name": user.name,
                    "user_email": getattr(user, "email", "") or "",
                    "ldap_provider": rep["provider"],
                    "reporter_top_level_group": rep["top_level"],
                    "reporter_group_path": rep["group_path"],
                    "reporter_group_ldap_linked": rep["ldap_linked"],
                    "other_top_level_group": other["top_level"],
                    "other_group_path": other["group_path"],
                    "other_group_ldap_linked": other["ldap_linked"],
                    "other_role_name": role_name(other["access_level"], other["member_role_id"]),
                    "other_access_level": other["access_level"],
                    "other_member_role_id": other["member_role_id"] or "",
                })

    out = f"reporter_conflicts_{datetime.now():%Y%m%d_%H%M%S}.csv"
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nDone. {len(rows)} conflict row(s) written to {out}")


if __name__ == "__main__":
    main()
