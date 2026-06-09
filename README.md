# GitLab Reporter Role Conflict Finder

Audits a GitLab Enterprise instance to find users who hold a **Reporter** role in one group while also holding a **different role** in another group. Only **active**, **LDAP-authenticated** users and **direct** memberships are evaluated — inherited memberships and blocked accounts are ignored.

Built on the [`python-gitlab`](https://python-gitlab.readthedocs.io/) library. Results are written to a timestamped CSV file.

---

## What it detects

A "conflict" is flagged when the same user appears as:

- **Reporter** (plain, no custom role) in at least one group
- **Any other role** in at least one other group

"Any other role" includes:

| Role | Type |
|---|---|
| Guest | Standard (access level 10) |
| Developer | Standard (access level 30) |
| Maintainer | Standard (access level 40) |
| Owner | Standard (access level 50) |
| appsec-vuln-approver | Custom role (member_role_id = 3) |
| Application_Owner | Custom role (member_role_id = 4) |

A user who is Reporter in group A **and** Developer in group B produces one row. A user who is Reporter in two groups and Developer in one produces two rows (one per Reporter group).

---

## Requirements

- Python 3.8 or newer
- A GitLab Personal Access Token with scopes:
  - `read_api` (read groups and memberships)
  - `read_user` (read user LDAP identities)

---

## Installation

```bash
cd o_reporter_duplicate_finder

# (recommended) virtual environment
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows

pip install -r requirements.txt
```

---

## Configuration

The script reads two environment variables:

| Variable | Description |
|---|---|
| `GITLAB_URL` | Base URL of your instance, e.g. `https://gitlab.example.com` |
| `GITLAB_TOKEN` | Personal Access Token |

### Option A — `.env` file (recommended)

```bash
cp .env.example .env
```

Edit `.env`:

```
GITLAB_URL=https://gitlab.example.com
GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
```

### Option B — inline

```bash
GITLAB_URL=https://gitlab.example.com GITLAB_TOKEN=glpat-xxx python gitlab_reporter_check.py
```

---

## Running

```bash
python gitlab_reporter_check.py
```

### Sample output

```
Connecting to https://gitlab.example.com ...
Found 87 groups (including subgroups).

[1/87] engineering
[2/87] engineering/backend
...
[87/87] security/appsec

Done. 23 conflict row(s) written to reporter_conflicts_20260609_143012.csv
```

---

## Output — CSV report

Written to `reporter_conflicts_YYYYMMDD_HHMMSS.csv` in the current directory.

| Column | Description |
|---|---|
| `username` | GitLab username |
| `user_display_name` | Full name |
| `user_email` | Primary email |
| `ldap_provider` | LDAP provider name, e.g. `ldapmain` |
| `reporter_top_level_group` | Top-level group of the Reporter membership |
| `reporter_group_path` | Full path of the group where they are Reporter |
| `reporter_group_ldap_linked` | `True` if that group has LDAP sync configured |
| `other_top_level_group` | Top-level group of the conflicting role |
| `other_group_path` | Full path of the conflicting group |
| `other_group_ldap_linked` | `True` if that group has LDAP sync configured |
| `other_role_name` | Conflicting role name (e.g. `Developer`, `Application_Owner`) |
| `other_access_level` | Numeric access level of the conflicting role |
| `other_member_role_id` | Custom role ID if applicable, otherwise blank |

---

## How it works

1. **List groups** — `gl.groups.list(all=True)` returns every group *and* subgroup (each subgroup is its own group). The top-level group is the first segment of `full_path`.
2. **LDAP link check** — `group.ldap_group_links.list()`; a non-empty result means the group has LDAP sync.
3. **Members** — `group.members.list(all=True)` returns direct members. Skips members whose `state` is not `active`, and skips any user without an LDAP identity (`gl.users.get(id).identities`, cached).
4. **Conflict detection** — for each user, split memberships into *plain Reporter* vs *everything else*. Flag users present in both, one CSV row per (Reporter group, other group) pair.

---

## Customising custom roles

Add new custom roles to the `CUSTOM_ROLES` dict near the top of `gitlab_reporter_check.py`:

```python
CUSTOM_ROLES = {3: "appsec-vuln-approver", 4: "Application_Owner", 5: "your-new-role"}
```

Find a role's `member_role_id` under **Admin > Roles**, or via `GET /groups/:id/member_roles`.

---

## Security note

The `.env` file holds a secret token — never commit it to version control.
