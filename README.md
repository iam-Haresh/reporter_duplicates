# GitLab Reporter Role Conflict Finder

Audits a GitLab Enterprise instance to find users who hold a **Reporter** role in one group while also holding a **different role** in another group. Only active, LDAP-authenticated users and direct memberships are evaluated — inherited memberships and blocked accounts are ignored.

Results are written to a timestamped CSV file that can be opened directly in Excel or Google Sheets.

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

A user who is Reporter in group A **and** Developer in group B will produce one row in the report. A user who is Reporter in two groups and Developer in one group will produce two rows (one per Reporter group).

---

## Requirements

- Python 3.10 or newer
- A GitLab Personal Access Token with the following scopes:
  - `read_api` (to read groups and memberships)
  - `read_user` (to read user identity/LDAP details)

---

## Installation

```bash
# 1. Clone or download this repository
cd o_reporter_duplicate_finder

# 2. (Recommended) create a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Configuration

The script reads two environment variables:

| Variable | Description |
|---|---|
| `GITLAB_URL` | Base URL of your GitLab instance, e.g. `https://gitlab.example.com` |
| `GITLAB_TOKEN` | Personal Access Token (PAT) |

### Option A — `.env` file (recommended)

```bash
cp .env.example .env
```

Edit `.env`:

```
GITLAB_URL=https://gitlab.example.com
GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
```

The script loads `.env` automatically on startup if it exists in the current directory.

### Option B — inline environment variables

```bash
GITLAB_URL=https://gitlab.example.com GITLAB_TOKEN=glpat-xxx python gitlab_reporter_check.py
```

### Option C — export in your shell session

```bash
export GITLAB_URL=https://gitlab.example.com
export GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
python gitlab_reporter_check.py
```

---

## Running the script

```bash
python gitlab_reporter_check.py
```

### Sample console output

```
Connecting to: https://gitlab.example.com
Found 12 top-level group(s). Expanding subgroups ...
Total groups discovered: 87

Checking LDAP group links ...
Groups with LDAP links: 34

[1/87] engineering  -> 5 active LDAP member(s)
[2/87] engineering/backend  -> 12 active LDAP member(s)
[3/87] engineering/backend/platform  -> 0 active LDAP member(s)
...
[87/87] security/appsec  -> 3 active LDAP member(s)

Unique users evaluated: 214 (189 LDAP-active)
Conflicts found: 23 row(s)
Report written to: reporter_conflicts_20260608_143012.csv
  23 row(s) written.

Summary: 87 groups scanned, 189 LDAP users evaluated, 23 conflict pairs.
```

---

## Output — CSV report

The report is written to `reporter_conflicts_YYYYMMDD_HHMMSS.csv` in the current directory.

### Column reference

| Column | Description |
|---|---|
| `username` | GitLab username (login handle) |
| `user_display_name` | Full name as shown in GitLab |
| `user_email` | Primary email address |
| `is_ldap_user` | `True` if the account has an LDAP identity |
| `ldap_provider` | LDAP provider name, e.g. `ldapmain` |
| `reporter_top_level_group` | Top-level group containing the Reporter membership |
| `reporter_group_name` | Display name of the specific group where they are Reporter |
| `reporter_group_path` | Full path of the Reporter group, e.g. `engineering/backend` |
| `reporter_group_ldap_linked` | `True` if the Reporter group has LDAP sync configured |
| `other_top_level_group` | Top-level group containing the conflicting role |
| `other_group_name` | Display name of the group with the conflicting role |
| `other_group_path` | Full path of the conflicting group |
| `other_group_ldap_linked` | `True` if the conflicting group has LDAP sync configured |
| `other_role_name` | Name of the conflicting role (e.g. `Developer`, `Application_Owner`) |
| `other_access_level` | Numeric access level of the conflicting role |
| `other_member_role_id` | Custom role ID if the role is a custom role, otherwise blank |

### Example rows

| username | reporter_group_path | other_group_path | other_role_name |
|---|---|---|---|
| jsmith | engineering/docs | security/appsec | Developer |
| alee | marketing | engineering/backend | Application_Owner |
| bwong | data/analytics | platform | Maintainer |

---

## How the script works

### Pipeline overview

```
collect_all_groups()
    └── _collect_subgroups() [recursive]
            ↓
populate_ldap_flags()
            ↓
collect_memberships()
    └── get_or_fetch_user() [cached]
            ↓
find_conflicts()
            ↓
write_csv()
```

### Step 1 — Group discovery (`collect_all_groups`)

Fetches all top-level groups, then recursively expands each group's subgroups using the GitLab subgroups API. Every group record stores its **top-level ancestor name and path** — captured once at the root and forwarded unchanged through every level of recursion — so all descendants correctly identify their root even when nested several levels deep.

### Step 2 — LDAP flag check (`populate_ldap_flags`)

For each group, calls the `/ldap_group_links` endpoint. If any LDAP group links are configured, the group is marked as `ldap_linked = True` in the report.

### Step 3 — Membership collection (`collect_memberships`)

For each group, fetches **direct members only** (not inherited). Applies two filters:
- **State filter**: skips members whose account state is not `active` (blocked, deactivated).
- **LDAP filter**: resolves each user's profile and skips any account that does not have an LDAP identity.

User profiles are fetched once and cached for the rest of the run.

### Step 4 — Conflict detection (`find_conflicts`)

For each user, splits their memberships into two groups:
- **Reporter records** — plain Reporter (access level 20, no custom role).
- **Other records** — everything else (different standard role or any custom role).

A user is flagged only when both groups are non-empty. The output is the cartesian product of the two groups, so every (Reporter group, conflicting group) pair appears as its own CSV row.

### Step 5 — Report output (`write_csv`)

Writes a UTF-8 BOM CSV so Excel opens it correctly without a manual encoding step.

---

## Customising custom roles

If your instance has additional custom roles, add them to the `CUSTOM_ROLE_NAMES` dict near the top of `gitlab_reporter_check.py`:

```python
CUSTOM_ROLE_NAMES: dict[int, str] = {
    3: "appsec-vuln-approver",
    4: "Application_Owner",
    5: "your-new-role",   # add new roles here
}
```

The `member_role_id` value can be found in GitLab under **Admin > Roles** or from the API endpoint `GET /groups/:id/member_roles`.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Error: GITLAB_TOKEN is not set` | Token env var missing | Set `GITLAB_TOKEN` in `.env` or as an env var |
| `HTTP 401 — Invalid or expired GITLAB_TOKEN` | Token is wrong or expired | Generate a new PAT in GitLab under User > Access Tokens |
| `HTTP 403` warnings on specific groups | Token lacks visibility of those groups | Use a token belonging to an admin user, or accept that those groups will be skipped |
| No rows in report | No Reporter users have conflicting roles, or no LDAP users found | Verify the token has `read_user` scope; check that users have LDAP identities configured |
| Script is slow | Large number of groups / users | Normal — the script prints progress per group; each unique user triggers one extra API call |
| `[rate limited] waiting Xs ...` | GitLab API rate limit hit | The script handles this automatically; no action needed |

---

## Security note

The `.env` file contains a secret token. It is listed in `.gitignore` by convention — ensure it is **never committed** to version control.
