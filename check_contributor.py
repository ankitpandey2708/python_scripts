#!/usr/bin/env python3
"""
Check a GitHub username's contributions across every repo in an org.

Usage:
    python check_contributor.py <username> [org]

Example:
    python check_contributor.py Floydimus02 covid19india

Requires: pip install requests
Optional: set GITHUB_TOKEN env var to avoid the 60 req/hr unauthenticated rate limit
          (bumps you to 5000 req/hr). No special scopes needed for public repo data.
"""

import sys
import os
import time
import requests

API = "https://api.github.com"


def get_headers():
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def get(url, params=None):
    resp = requests.get(url, headers=get_headers(), params=params)
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        print("ERROR: GitHub API rate limit exceeded.")
        print("Set a token: export GITHUB_TOKEN=your_token_here (no scopes needed for public data)")
        sys.exit(1)
    return resp


def get_all_repos(org):
    repos = []
    page = 1
    while True:
        resp = get(f"{API}/orgs/{org}/repos", params={"per_page": 100, "page": page})
        if resp.status_code != 200:
            print(f"ERROR fetching repos: {resp.status_code} {resp.text[:200]}")
            sys.exit(1)
        batch = resp.json()
        if not batch:
            break
        repos.extend(r["name"] for r in batch)
        page += 1
    return repos


def check_contributors(org, repo, username):
    resp = get(f"{API}/repos/{org}/{repo}/contributors", params={"per_page": 100, "anon": "true"})
    if resp.status_code != 200:
        return None
    for c in resp.json():
        if str(c.get("login", "")).lower() == username.lower():
            return c.get("contributions", "unknown")
    return None


def search_commits(org, username):
    resp = get(f"{API}/search/commits", params={"q": f"org:{org} author:{username}"})
    if resp.status_code != 200:
        print(f"Commit search failed: {resp.status_code} {resp.text[:200]}")
        return
    data = resp.json()
    total = data.get("total_count", 0)
    print(f"Total commits found via search API: {total}")
    for item in data.get("items", [])[:20]:
        repo = item["repository"]["full_name"]
        sha = item["sha"][:7]
        msg = item["commit"]["message"].split("\n")[0][:80]
        print(f"  - {repo} [{sha}]: {msg}")


def search_issues(org, username):
    resp = get(f"{API}/search/issues", params={"q": f"org:{org} author:{username}"})
    if resp.status_code != 200:
        print(f"Issue/PR search failed: {resp.status_code} {resp.text[:200]}")
        return
    data = resp.json()
    total = data.get("total_count", 0)
    print(f"Total PRs/issues found: {total}")
    for item in data.get("items", [])[:20]:
        kind = "PR" if item.get("pull_request") else "Issue"
        repo_name = item["repository_url"].split("/")[-1]
        print(f"  - [{kind}] {repo_name}: {item['title']} ({item['html_url']})")


def main():
    username = sys.argv[1] if len(sys.argv) > 1 else "Floydimus02"
    org = sys.argv[2] if len(sys.argv) > 2 else "covid19india"

    print(f"Checking contributions by '{username}' across all repos in org '{org}'")
    print("=" * 72)

    repos = get_all_repos(org)
    found_any = False

    for repo in repos:
        commits = check_contributors(org, repo, username)
        if commits is not None:
            print(f"[{repo}] -> FOUND as contributor. Commits: {commits}")
            found_any = True
        else:
            print(f"[{repo}] -> not in contributors list")
        time.sleep(0.3)

    print("=" * 72)
    if found_any:
        print(f"RESULT: '{username}' found as a contributor in at least one repo (see above).")
    else:
        print(f"RESULT: '{username}' not found in any repo's contributors list.")
        print("NOTE: this only catches commits linked to their GitHub account.")

    print()
    print("Cross-check 1: Commit search (catches commits not surfaced via contributors list)")
    print("-" * 72)
    search_commits(org, username)

    print()
    print("Cross-check 2: PRs/issues authored by this user across the org")
    print("-" * 72)
    search_issues(org, username)


if __name__ == "__main__":
    main()
