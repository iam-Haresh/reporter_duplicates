"""
GitLab Enterprise — Reporter Role Conflict Finder

Purpose
-------
Scans every group and subgroup on a GitLab Enterprise instance and identifies
active LDAP users who hold a Reporter role in at least one group while also
holding a different role (Guest, Developer, Maintainer, Owner, or a custom role
such as appsec-vuln-approver or Application_Owner) in another group.

Only direct memberships are evaluated — inherited memberships from parent groups
are ignored. Blocked / deactivated users and non-LDAP accounts are excluded.

Output
------
A timestamped CSV file named  reporter_conflicts_YYYYMMDD_HHMMSS.csv  is written
to the current working directory. Each row represents one (reporter-group,
other-role-group) pair for a flagged user.

Usage
-----
    # Option A — environment variables inline
    GITLAB_URL=https://gitlab.example.com GITLAB_TOKEN=glpat-xxx python gitlab_reporter_check.py

    # Option B — .env file in the same directory
    cp .env.example .env          # then edit with real values
    python gitlab_reporter_check.py

Required token scopes
---------------------
    read_api  (or api)
    read_user
"""

from __future__ import annotations

import csv
import dataclasses
import os
import sys
import time
from datetime import datetime
from typing import Optional

import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maps GitLab's numeric access_level to a human-readable role name.
# These are the standard built-in roles in GitLab.
ACCESS_LEVEL_NAMES: dict[int, str] = {
    10: "Guest",
    20: "Reporter",
    30: "Developer",
    40: "Maintainer",
    50: "Owner",
}

# Custom roles specific to this GitLab Enterprise instance.
# The key is the member_role_id returned by the API.
# Update these if new custom roles are created on the instance.
CUSTOM_ROLE_NAMES: dict[int, str] = {
    3: "appsec-vuln-approver",
    4: "Application_Owner",
}

# Access level for the Reporter role — used throughout as the pivot point.
REPORTER_LEVEL = 20

# Maximum number of times to retry a failed HTTP request before giving up.
MAX_RETRIES = 5

# Ordered list of columns written to the CSV output.
# Changing the order here changes column order in the report.
CSV_COLUMNS = [
    "username",
    "user_display_name",
    "user_email",
    "is_ldap_user",
    "ldap_provider",
    "reporter_top_level_group",
    "reporter_group_name",
    "reporter_group_path",
    "reporter_group_ldap_linked",
    "other_top_level_group",
    "other_group_name",
    "other_group_path",
    "other_group_ldap_linked",
    "other_role_name",
    "other_access_level",
    "other_member_role_id",
]

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class GroupInfo:
    """
    Represents a single GitLab group or subgroup.

    Attributes
    ----------
    id                   : GitLab internal group ID.
    name                 : Display name of the group (not the full path).
    full_path            : Slash-separated path from the root namespace,
                           e.g. "engineering/backend/platform".
    top_level_group_name : Display name of the root ancestor group.
                           Set when the group is first discovered and never
                           changed during recursion, so every subgroup at any
                           depth always knows its true top-level ancestor.
    top_level_group_path : Full path of the root ancestor, e.g. "engineering".
    ldap_linked          : True if the group has at least one LDAP group link
                           configured (populated by populate_ldap_flags).
    """

    id: int
    name: str
    full_path: str
    top_level_group_name: str
    top_level_group_path: str
    ldap_linked: bool = False


@dataclasses.dataclass
class MembershipRecord:
    """
    Represents one direct membership of a user in a specific group.

    A single user can have many MembershipRecords — one per group they belong
    to. The conflict-detection step compares all records for the same user to
    find mismatched roles.

    Attributes
    ----------
    group_id              : GitLab internal group ID.
    group_name            : Display name of the group.
    group_path            : Full slash-separated path of the group.
    top_level_group_name  : Root ancestor display name (carried from GroupInfo).
    top_level_group_path  : Root ancestor full path (carried from GroupInfo).
    ldap_linked           : Whether the group has LDAP sync configured.
    access_level          : Numeric role — 10/20/30/40/50 for the standard roles.
    member_role_id        : Set when the user has a custom role (e.g. 3 or 4).
                            None for standard role-only memberships.
    """

    group_id: int
    group_name: str
    group_path: str
    top_level_group_name: str
    top_level_group_path: str
    ldap_linked: bool
    access_level: int
    member_role_id: Optional[int]


@dataclasses.dataclass
class UserProfile:
    """
    Cached GitLab user details fetched from GET /api/v4/users/:id.

    Fetched once per unique user and reused throughout the run to avoid
    redundant API calls. is_ldap_user and ldap_provider are derived from
    the user's identities array in the API response.

    Attributes
    ----------
    id           : GitLab internal user ID.
    username     : GitLab username (login handle).
    name         : Full display name.
    email        : Primary email address (may be empty for some accounts).
    is_ldap_user : True if the user has at least one LDAP identity on record.
    ldap_provider: The provider name of the first matched LDAP identity,
                   e.g. "ldapmain". Empty string when is_ldap_user is False.
    """

    id: int
    username: str
    name: str
    email: str
    is_ldap_user: bool
    ldap_provider: str


# ---------------------------------------------------------------------------
# GitLab API client
# ---------------------------------------------------------------------------


class GitLabClient:
    """
    Thin HTTP client for the GitLab REST API v4.

    Handles authentication, pagination, and transient error retries so that
    all higher-level functions can focus on business logic without worrying
    about HTTP details.

    All requests use a persistent requests.Session so TCP connections are
    reused across calls, reducing latency on large scans.
    """

    def __init__(self, base_url: str, token: str) -> None:
        """
        Initialise the client.

        Parameters
        ----------
        base_url : Root URL of the GitLab instance, e.g. "https://gitlab.example.com".
                   Trailing slashes are stripped automatically.
        token    : A Personal Access Token with at least read_api and read_user
                   scopes. Injected as the PRIVATE-TOKEN header on every request.
        """
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"PRIVATE-TOKEN": token})

    def _get(self, path: str, params: dict | None = None) -> requests.Response:
        """
        Perform a single authenticated GET request with retry logic.

        Retries are attempted for:
          - Connection errors (network blip) — up to MAX_RETRIES times with a
            5-second gap between attempts.
          - HTTP 429 Too Many Requests — waits for the duration specified in
            the Retry-After response header before retrying.
          - HTTP 5xx Server Error — retries up to MAX_RETRIES times with a
            5-second gap.

        Raises immediately (no retry) for:
          - HTTP 401: token is invalid or expired.
          - HTTP 403: token lacks permission for this resource.
          - HTTP 404: the resource does not exist.

        Parameters
        ----------
        path   : API path relative to /api/v4, e.g. "/groups/10/members".
        params : Optional query parameters dict.

        Returns
        -------
        requests.Response with a 2xx status code.

        Raises
        ------
        RuntimeError     : Connection error exhausted retries, or 401 received.
        PermissionError  : HTTP 403 Forbidden.
        LookupError      : HTTP 404 Not Found.
        """
        url = f"{self.base_url}/api/v4{path}"
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = self.session.get(url, params=params, timeout=30)
            except requests.ConnectionError as exc:
                if attempt == MAX_RETRIES:
                    raise RuntimeError(f"Connection error after {MAX_RETRIES} retries: {exc}") from exc
                time.sleep(5)
                continue

            if resp.status_code == 429:
                # GitLab enforces per-token and per-IP rate limits.
                # Honor the Retry-After header; add 1 second of buffer.
                retry_after = int(resp.headers.get("Retry-After", 60))
                print(f"  [rate limited] waiting {retry_after}s ...", file=sys.stderr)
                time.sleep(retry_after + 1)
                continue

            if resp.status_code == 401:
                raise RuntimeError("HTTP 401 — Invalid or expired GITLAB_TOKEN")

            if resp.status_code == 403:
                # Raised so callers can catch PermissionError and skip gracefully.
                raise PermissionError(f"HTTP 403 — Forbidden: {url}")

            if resp.status_code == 404:
                # Raised so callers can catch LookupError and handle missing resources.
                raise LookupError(f"HTTP 404 — Not found: {url}")

            if resp.status_code >= 500:
                if attempt < MAX_RETRIES:
                    time.sleep(5)
                    continue
                resp.raise_for_status()

            resp.raise_for_status()
            return resp

        raise RuntimeError(f"Exhausted {MAX_RETRIES} retries for {url}")

    def get_paginated(self, path: str, params: dict | None = None) -> list[dict]:
        """
        Fetch all pages of a paginated GitLab list endpoint.

        GitLab returns up to `per_page` items per response and signals the
        next page via the X-Next-Page response header. This method keeps
        fetching until X-Next-Page is empty, then returns the accumulated list.

        HTTP 403 responses are treated as a soft failure: a warning is printed
        and an empty list is returned so the caller can continue with other groups.

        Parameters
        ----------
        path   : API path relative to /api/v4.
        params : Extra query parameters. per_page defaults to 100 if not set.

        Returns
        -------
        Flat list of all items across all pages.
        """
        params = dict(params or {})
        params.setdefault("per_page", 100)
        params["page"] = 1
        results: list[dict] = []

        while True:
            try:
                resp = self._get(path, params)
            except PermissionError as exc:
                # Skip inaccessible groups rather than aborting the entire run.
                print(f"  warning: {exc}", file=sys.stderr)
                break

            data = resp.json()
            if not isinstance(data, list):
                # Unexpected response shape — stop pagination for this endpoint.
                break
            results.extend(data)

            # X-Next-Page is an integer string when another page exists, or "" when done.
            next_page = resp.headers.get("X-Next-Page", "").strip()
            if not next_page:
                break
            params["page"] = int(next_page)

        return results

    def get_all_top_level_groups(self) -> list[dict]:
        """
        Return all top-level (root) groups visible to the token.

        Uses top_level_only=true so subgroups are excluded here — they are
        fetched separately via get_subgroups to preserve the parent-child
        relationship needed for top-level group attribution.
        """
        return self.get_paginated("/groups", {"top_level_only": "true"})

    def get_subgroups(self, group_id: int) -> list[dict]:
        """
        Return the immediate child subgroups of a given group.

        Only direct children are returned per API call. Deeper descendants
        are discovered by calling this method recursively from _collect_subgroups.

        Parameters
        ----------
        group_id : GitLab ID of the parent group.
        """
        return self.get_paginated(f"/groups/{group_id}/subgroups")

    def get_ldap_group_links(self, group_id: int) -> list[dict]:
        """
        Return the LDAP group links configured for a group.

        A non-empty list means the group is synchronised with an LDAP group —
        members may be added/removed automatically by LDAP sync jobs.
        Returns an empty list if the group has no LDAP links or if the token
        lacks permission to read them.

        Parameters
        ----------
        group_id : GitLab ID of the group to check.
        """
        try:
            resp = self._get(f"/groups/{group_id}/ldap_group_links")
            return resp.json() if isinstance(resp.json(), list) else []
        except (PermissionError, LookupError):
            return []

    def get_direct_members(self, group_id: int) -> list[dict]:
        """
        Return the direct members of a group (not inherited from parent groups).

        Uses /groups/:id/members (not /groups/:id/members/all) so that users
        who only inherit access from an ancestor group are excluded.

        Parameters
        ----------
        group_id : GitLab ID of the group.
        """
        return self.get_paginated(f"/groups/{group_id}/members")

    def get_user(self, user_id: int) -> dict:
        """
        Fetch the full user record including the identities array.

        The identities array is used to determine whether the user authenticated
        via LDAP. Returns an empty dict if the user is not found (HTTP 404).

        Parameters
        ----------
        user_id : GitLab internal user ID.
        """
        try:
            resp = self._get(f"/users/{user_id}")
            return resp.json()
        except LookupError:
            return {}


# ---------------------------------------------------------------------------
# Group discovery
# ---------------------------------------------------------------------------


def collect_all_groups(client: GitLabClient) -> dict[int, GroupInfo]:
    """
    Build a flat dictionary of every group and subgroup on the instance.

    Strategy
    --------
    1. Fetch all top-level groups via get_all_top_level_groups.
    2. For each top-level group, call _collect_subgroups to depth-first expand
       all descendants.
    3. Every GroupInfo records top_level_group_name and top_level_group_path,
       which are captured at depth 0 (the root) and passed unchanged through
       every level of recursion. This guarantees that all descendants — no matter
       how deeply nested — correctly identify their root ancestor.

    Parameters
    ----------
    client : Authenticated GitLabClient instance.

    Returns
    -------
    dict mapping group_id (int) -> GroupInfo for every group discovered.
    """
    groups: dict[int, GroupInfo] = {}
    top_level = client.get_all_top_level_groups()
    print(f"Found {len(top_level)} top-level group(s). Expanding subgroups ...")

    for raw in top_level:
        info = GroupInfo(
            id=raw["id"],
            name=raw["name"],
            full_path=raw["full_path"],
            # Both top_level fields are set to this group's own values since
            # it IS the top-level ancestor. These values are forwarded unchanged
            # to every descendant during recursion.
            top_level_group_name=raw["name"],
            top_level_group_path=raw["full_path"],
        )
        groups[info.id] = info
        _collect_subgroups(client, info.id, info.name, info.full_path, groups)

    return groups


def _collect_subgroups(
    client: GitLabClient,
    parent_id: int,
    top_level_name: str,
    top_level_path: str,
    groups: dict[int, GroupInfo],
) -> None:
    """
    Recursively discover and register all subgroups under a parent group.

    This is the recursive helper called by collect_all_groups. It fetches the
    immediate children of parent_id and for each child:
      - Creates a GroupInfo with top_level_name/top_level_path inherited from
        the root (never the direct parent), ensuring correct attribution at any depth.
      - Adds the child to the shared groups dict.
      - Recurses to expand the child's own children.

    The groups dict is mutated in place; no return value is needed.

    Parameters
    ----------
    client          : Authenticated GitLabClient instance.
    parent_id       : ID of the group whose children should be fetched.
    top_level_name  : Display name of the root ancestor — passed unchanged at every level.
    top_level_path  : Full path of the root ancestor — passed unchanged at every level.
    groups          : Shared accumulator dict (mutated in place).
    """
    children = client.get_subgroups(parent_id)
    for raw in children:
        info = GroupInfo(
            id=raw["id"],
            name=raw["name"],
            full_path=raw["full_path"],
            # Carry the root ancestor values forward unchanged so this subgroup
            # and all its descendants know their ultimate top-level group.
            top_level_group_name=top_level_name,
            top_level_group_path=top_level_path,
        )
        groups[info.id] = info
        _collect_subgroups(client, info.id, top_level_name, top_level_path, groups)


# ---------------------------------------------------------------------------
# LDAP flags
# ---------------------------------------------------------------------------


def populate_ldap_flags(client: GitLabClient, groups: dict[int, GroupInfo]) -> None:
    """
    Check every group for LDAP group links and set GroupInfo.ldap_linked.

    A group is considered LDAP-linked if the /ldap_group_links endpoint returns
    at least one entry. This is a group-level configuration that indicates the
    group's membership is (or can be) synchronised with an external LDAP directory.

    This is a separate pass from group discovery so that all GroupInfo objects
    exist before any MembershipRecord references their ldap_linked flag.

    Parameters
    ----------
    client : Authenticated GitLabClient instance.
    groups : The groups dict produced by collect_all_groups (mutated in place).
    """
    print("Checking LDAP group links ...")
    for group in groups.values():
        links = client.get_ldap_group_links(group.id)
        group.ldap_linked = len(links) > 0


# ---------------------------------------------------------------------------
# Membership collection
# ---------------------------------------------------------------------------


def get_or_fetch_user(
    client: GitLabClient,
    user_id: int,
    user_cache: dict[int, UserProfile],
) -> UserProfile:
    """
    Return a UserProfile for the given user ID, fetching from the API if needed.

    The user_cache dict acts as an in-memory store so each user is fetched at
    most once per script run, regardless of how many groups they belong to.

    LDAP detection
    --------------
    The GitLab API returns an "identities" list on the user record. Each entry
    has a "provider" field. If any provider name starts with "ldap", the user
    is treated as an LDAP user and that provider name is stored. The first
    matching provider is used; additional LDAP providers (rare) are ignored.

    If the user record cannot be fetched (HTTP 404, deleted account), a stub
    UserProfile with is_ldap_user=False is returned so the caller can safely
    skip the user without crashing.

    Parameters
    ----------
    client     : Authenticated GitLabClient instance.
    user_id    : GitLab internal user ID.
    user_cache : Shared dict from user_id -> UserProfile (mutated in place).

    Returns
    -------
    UserProfile — either from cache or freshly fetched.
    """
    if user_id in user_cache:
        return user_cache[user_id]

    raw = client.get_user(user_id)
    if not raw:
        # User not found (deleted or 404) — create a non-LDAP stub so the
        # caller can still skip this user cleanly.
        profile = UserProfile(
            id=user_id,
            username="",
            name="",
            email="",
            is_ldap_user=False,
            ldap_provider="",
        )
        user_cache[user_id] = profile
        return profile

    # Scan the identities list for any LDAP provider.
    # GitLab uses provider names like "ldapmain", "ldapsecondary", etc.
    ldap_provider = ""
    for identity in raw.get("identities", []):
        provider = identity.get("provider", "")
        if provider.startswith("ldap"):
            ldap_provider = provider
            break

    profile = UserProfile(
        id=user_id,
        username=raw.get("username", ""),
        name=raw.get("name", ""),
        # email can be null for some account types; default to empty string.
        email=raw.get("email", "") or "",
        is_ldap_user=bool(ldap_provider),
        ldap_provider=ldap_provider,
    )
    user_cache[user_id] = profile
    return profile


def collect_memberships(
    client: GitLabClient,
    groups: dict[int, GroupInfo],
    user_cache: dict[int, UserProfile],
) -> dict[int, list[MembershipRecord]]:
    """
    Build a per-user index of all direct, active LDAP memberships across every group.

    For each group this function:
      1. Fetches direct members (not inherited) via get_direct_members.
      2. Skips members whose state is not "active" (blocks, deactivated accounts).
      3. Resolves each member's UserProfile (fetched once, then cached).
      4. Skips non-LDAP users.
      5. Appends a MembershipRecord to the user's entry in the memberships dict.

    A (user_id, group_id) set is used to deduplicate in case the API ever
    returns the same member twice for the same group.

    The member_role_id field — present only in GitLab EE for custom roles —
    is read with .get() so the code is safe against instances or API versions
    where the field is absent.

    Parameters
    ----------
    client     : Authenticated GitLabClient instance.
    groups     : All discovered groups (from collect_all_groups + populate_ldap_flags).
    user_cache : Shared user cache dict (mutated in place by get_or_fetch_user).

    Returns
    -------
    dict mapping user_id (int) -> list[MembershipRecord] for every qualifying member.
    """
    memberships: dict[int, list[MembershipRecord]] = {}
    seen: set[tuple[int, int]] = set()  # Guards against duplicate (user, group) pairs.

    group_list = list(groups.values())
    total = len(group_list)

    for idx, group in enumerate(group_list, start=1):
        print(f"[{idx}/{total}] {group.full_path}", end="", flush=True)

        raw_members = client.get_direct_members(group.id)
        active_ldap_count = 0

        for m in raw_members:
            # Only active users are in scope — skip blocked/deactivated accounts.
            if m.get("state") != "active":
                continue

            uid = m["id"]
            key = (uid, group.id)
            if key in seen:
                continue
            seen.add(key)

            profile = get_or_fetch_user(client, uid, user_cache)
            # Only LDAP-authenticated users are in scope for this audit.
            if not profile.is_ldap_user:
                continue

            active_ldap_count += 1
            record = MembershipRecord(
                group_id=group.id,
                group_name=group.name,
                group_path=group.full_path,
                top_level_group_name=group.top_level_group_name,
                top_level_group_path=group.top_level_group_path,
                ldap_linked=group.ldap_linked,
                access_level=m.get("access_level", 0),
                # member_role_id is a GitLab EE-only field for custom roles.
                # Use `or None` to normalise falsy values (0, False) to None.
                member_role_id=m.get("member_role_id") or None,
            )
            memberships.setdefault(uid, []).append(record)

        print(f"  -> {active_ldap_count} active LDAP member(s)")

    return memberships


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------


def resolve_role_name(access_level: int, member_role_id: Optional[int]) -> str:
    """
    Return a human-readable role name for a membership record.

    Custom roles (member_role_id is not None) take precedence over the base
    access_level name. Unknown custom role IDs fall back to "custom_role_<id>"
    so the CSV always has a readable label even if CUSTOM_ROLE_NAMES is stale.

    Parameters
    ----------
    access_level   : Numeric GitLab access level (10, 20, 30, 40, or 50).
    member_role_id : Custom role ID for EE custom roles, or None.

    Returns
    -------
    Human-readable role name string.
    """
    if member_role_id is not None:
        return CUSTOM_ROLE_NAMES.get(member_role_id, f"custom_role_{member_role_id}")
    return ACCESS_LEVEL_NAMES.get(access_level, str(access_level))


def find_conflicts(
    memberships: dict[int, list[MembershipRecord]],
    user_cache: dict[int, UserProfile],
) -> list[dict]:
    """
    Identify users who are a plain Reporter in one group and hold a different
    role in another group, then produce one CSV row per conflict pair.

    Partitioning logic
    ------------------
    For each user's membership list, records are split into two buckets:

      reporter_records — memberships where access_level == 20 (Reporter) AND
                         member_role_id is None (plain Reporter, no custom role).

      other_records    — all remaining memberships. This includes:
                           • Any non-Reporter standard role (Guest, Developer, etc.)
                           • Any membership with a custom role (member_role_id set),
                             even if the base access_level is still 20 — because a
                             custom role represents elevated or specialised permissions
                             beyond plain Reporter.

    A user is flagged only if BOTH buckets are non-empty. The output is the
    cartesian product of reporter_records × other_records, producing one row
    per (reporter-group, other-role-group) pair to make every conflict visible
    and independently filterable in the CSV.

    Parameters
    ----------
    memberships : Per-user membership index from collect_memberships.
    user_cache  : User details cache from get_or_fetch_user.

    Returns
    -------
    List of row dicts keyed by CSV_COLUMNS, ready for write_csv.
    """
    rows: list[dict] = []

    for user_id, records in memberships.items():
        profile = user_cache[user_id]

        # Plain Reporter memberships (no custom role overlay).
        reporter_records = [
            r for r in records
            if r.access_level == REPORTER_LEVEL and r.member_role_id is None
        ]
        # Everything else — different standard role OR any custom role.
        other_records = [
            r for r in records
            if not (r.access_level == REPORTER_LEVEL and r.member_role_id is None)
        ]

        # Only flag the user if they appear in both buckets.
        if not reporter_records or not other_records:
            continue

        # Cartesian product: one row per (reporter group, conflicting group) pair.
        for rep in reporter_records:
            for other in other_records:
                rows.append({
                    "username": profile.username,
                    "user_display_name": profile.name,
                    "user_email": profile.email,
                    "is_ldap_user": profile.is_ldap_user,
                    "ldap_provider": profile.ldap_provider,
                    "reporter_top_level_group": rep.top_level_group_name,
                    "reporter_group_name": rep.group_name,
                    "reporter_group_path": rep.group_path,
                    "reporter_group_ldap_linked": rep.ldap_linked,
                    "other_top_level_group": other.top_level_group_name,
                    "other_group_name": other.group_name,
                    "other_group_path": other.group_path,
                    "other_group_ldap_linked": other.ldap_linked,
                    "other_role_name": resolve_role_name(other.access_level, other.member_role_id),
                    "other_access_level": other.access_level,
                    # Leave other_member_role_id blank for standard roles to keep the CSV clean.
                    "other_member_role_id": other.member_role_id if other.member_role_id is not None else "",
                })

    return rows


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------


def write_csv(rows: list[dict], output_path: str) -> None:
    """
    Write the conflict rows to a CSV file.

    Encoding is utf-8-sig (UTF-8 with BOM) so that Excel on macOS and Windows
    automatically detects the encoding and renders non-ASCII characters — such
    as accented names or non-Latin usernames — correctly without a manual import
    step.

    An empty file with only the header row is written when rows is empty, so
    the caller always gets a usable CSV even when no conflicts are found.

    Parameters
    ----------
    rows        : List of row dicts produced by find_conflicts.
    output_path : Destination file path for the CSV.
    """
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Report written to: {output_path}")
    print(f"  {len(rows)} row(s) written.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """
    Orchestrate the full audit pipeline and write the CSV report.

    Pipeline steps
    --------------
    1. Load configuration from environment / .env file.
    2. Discover all groups and subgroups (collect_all_groups).
    3. Check each group for LDAP sync configuration (populate_ldap_flags).
    4. Collect direct, active LDAP memberships per user (collect_memberships).
    5. Identify Reporter users with conflicting roles (find_conflicts).
    6. Write the timestamped CSV report (write_csv).
    7. Print a summary line.

    Exits with code 1 if GITLAB_TOKEN or GITLAB_URL are not set.
    """
    load_dotenv()

    token = os.environ.get("GITLAB_TOKEN", "").strip()
    base_url = os.environ.get("GITLAB_URL", "").strip()

    if not token:
        print("Error: GITLAB_TOKEN is not set.", file=sys.stderr)
        sys.exit(1)
    if not base_url:
        print("Error: GITLAB_URL is not set.", file=sys.stderr)
        sys.exit(1)

    client = GitLabClient(base_url, token)

    print(f"Connecting to: {base_url}")
    groups = collect_all_groups(client)
    print(f"Total groups discovered: {len(groups)}\n")

    populate_ldap_flags(client, groups)
    ldap_linked_count = sum(1 for g in groups.values() if g.ldap_linked)
    print(f"Groups with LDAP links: {ldap_linked_count}\n")

    user_cache: dict[int, UserProfile] = {}
    memberships = collect_memberships(client, groups, user_cache)

    ldap_users = sum(1 for p in user_cache.values() if p.is_ldap_user)
    print(f"\nUnique users evaluated: {len(user_cache)} ({ldap_users} LDAP-active)")

    rows = find_conflicts(memberships, user_cache)

    if not rows:
        print("No conflicts found.")
    else:
        print(f"Conflicts found: {len(rows)} row(s)")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"reporter_conflicts_{timestamp}.csv"
    write_csv(rows, output_path)

    print(f"\nSummary: {len(groups)} groups scanned, {ldap_users} LDAP users evaluated, {len(rows)} conflict pairs.")


if __name__ == "__main__":
    main()
