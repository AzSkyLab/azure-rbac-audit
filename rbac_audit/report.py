"""report.html: one self-contained page per run for reviewers (no scripts, no external assets). Written before the
manifest, so it is hashed like every other evidence file. Every value is HTML-escaped: principal and group names are
attacker-influenced. Tables are capped; the CSVs remain the complete record."""
from __future__ import annotations

from html import escape

MAX_ROWS = 300

# (title, control, csv, columns shown, one-line explanation)
SECTIONS = [
    ("Standing privileged Azure access", "AC-6", "exceptions_privileged_permanent.csv",
     ["role_name", "scope", "principal_type", "principal_name", "principal_upn_or_appid", "created_on"],
     "Privileged Azure roles held permanently (not through PIM activation or a time-bound assignment)."),
    ("Standing privileged Entra roles", "AC-6", "exceptions_entra_privileged_permanent.csv",
     ["role_name", "principal_type", "principal_name", "principal_upn_or_appid", "role_privileged"],
     "Privileged Entra directory roles held permanently."),
    ("Roles assigned directly to users", "AC-2", "exceptions_direct_user.csv",
     ["role_name", "scope", "principal_type", "principal_name", "principal_upn_or_appid", "pim_label"],
     "Azure roles held by a user or guest instead of a group."),
    ("Inactive or disabled privileged accounts", "AC-2(3)", "inactive_privileged_accounts.csv",
     ["principal_name", "upn", "reason", "detail", "last_sign_in", "privileged_access"],
     "Accounts with privileged access that are disabled, pending guests, or have not signed in recently."),
    ("Standing members of privileged groups", "AC-2(7)", "exceptions_privileged_group_standing.csv",
     ["privileged_group_name", "member_name", "member_upn_or_appid", "access", "label", "path"],
     "Users who are permanent (non-PIM) members or owners of a privileged group."),
    ("Access review exceptions", "AC-2(j), AC-6(7)", "exceptions_access_review.csv",
     ["group_name", "reason", "detail"],
     "Privileged groups without an effective access review."),
    ("Access reviews of deleted groups", "AC-2(j)", "access_reviews_stale.csv",
     ["definition_name", "target_group_id", "detail"],
     "Active reviews whose target group no longer exists."),
    ("Accepted exceptions", "", "exceptions_allowlisted.csv",
     ["exception_file", "principal_name", "role_name", "scope", "allowlist_reason"],
     "Exceptions accepted through exception_allowlist, with the recorded reason."),
]

_CSS = """
:root{--bg:#fbfbfa;--fg:#1d1d1b;--muted:#6b6b66;--line:#e2e1dc;--card:#fff;--ok:#1f7a4d;--bad:#b3261e;--warn:#8a5a00}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--muted:#a3a29b;--line:#34332f;--card:#1f1f1d;
--ok:#5cc28f;--bad:#f2867c;--warn:#e0b45c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 4px}
.muted{color:var(--muted)}.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-weight:600;font-size:12px}
.ok{color:var(--ok);border:1px solid var(--ok)}.bad{color:var(--bad);border:1px solid var(--bad)}
.warn{color:var(--warn);border:1px solid var(--warn)}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:8px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.tile b{display:block;font-size:22px}.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);
vertical-align:top}th{position:sticky;top:0;background:var(--card)}td{overflow-wrap:anywhere}ul{margin:4px 0 0 18px;padding:0}
"""


_LABELS = {"principal_upn_or_appid": "UPN / app id", "member_upn_or_appid": "UPN / app id", "upn": "UPN",
           "pim_label": "PIM label", "role_privileged": "privileged role"}


def _cell(row: dict, col: str) -> str:
    value = row.get(col, "")
    if col in ("principal_name", "member_name") and not value:  # deleted principal: show which one
        ident = row.get("principal_id") or row.get("member_id") or ""
        return f'<span class=muted>{escape(str(ident))}</span>' if ident else ""
    return escape(str(value))


def _table(columns: list[str], rows: list[dict]) -> str:
    head = "".join(f"<th>{escape(_LABELS.get(c, c.replace('_', ' ')))}</th>" for c in columns)
    body = "".join("<tr>" + "".join(f"<td>{_cell(r, c)}</td>" for c in columns) + "</tr>" for r in rows[:MAX_ROWS])
    more = f'<p class="muted">Showing {MAX_ROWS} of {len(rows)} rows; see the CSV.</p>' if len(rows) > MAX_ROWS else ""
    return f'<div class="wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>{more}'


def render(info: dict, tables: dict[str, list[dict]]) -> str:
    """`info`: the manifest content (without files); `tables`: csv name -> rows."""
    s, ident = info.get("summary") or {}, info.get("signed_in_identity") or {}
    complete = bool(s.get("coverage_complete"))
    who = ident.get("upn") or ident.get("app_id") or ident.get("object_id") or "unknown"
    tiles = [("Assignments", s.get("assignments_total")), ("Privileged groups", s.get("privileged_groups")),
             ("Entra role holders", s.get("entra_role_assignments"))]
    tiles += [(title, len(tables.get(csv_name, []))) for title, _, csv_name, _, _ in SECTIONS[:6]]
    out = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        '<meta name=viewport content="width=device-width,initial-scale=1">',
        f"<title>RBAC audit {escape(str(info.get('run_started_utc', '')))}</title><style>{_CSS}</style></head><body><main>",
        "<h1>Azure RBAC and Entra privileged access audit</h1>",
        f'<p class=muted>Tenant {escape(str(ident.get("tenant_id") or ""))} · run {escape(str(info.get("run_started_utc", "")))}'
        f' to {escape(str(info.get("run_finished_utc", "")))} · collector {escape(str(who))}'
        f' · rbac-audit {escape(str(info.get("tool_version", "")))}</p>',
        f'<p><span class="badge {"ok" if complete else "bad"}">{"Coverage complete" if complete else "Coverage INCOMPLETE: results are not conclusive"}</span>'
        f' <span class=muted>Verify this page and every file against manifest.json / manifest.sha256.</span></p>',
        '<div class=tiles>' + "".join(f'<div class=tile><b>{escape(str(v if v is not None else "-"))}</b>'
                                      f'<span class=muted>{escape(t)}</span></div>' for t, v in tiles) + "</div>",
    ]
    gaps = s.get("coverage_gaps_by_area") or {}
    if gaps or s.get("missing_graph_permissions"):
        out.append('<h2>Coverage gaps</h2><p class=muted>Anything here is unknown, never a pass.</p><ul>')
        out += [f"<li><b>{escape(area)}</b>: {escape(m)}</li>" for area, msgs in gaps.items() for m in msgs]
        if s.get("missing_graph_permissions"):
            out.append(f"<li><b>missing Graph permissions</b>: {escape(', '.join(s['missing_graph_permissions']))}</li>")
        out.append("</ul>")
    for title, control, csv_name, columns, why in SECTIONS:
        rows = tables.get(csv_name, [])
        tag = f' <span class="badge {"warn" if rows else "ok"}">{len(rows)}</span>'
        out.append(f"<h2>{escape(title)}{tag}</h2><p class=muted>{escape(why)}"
                   f"{(' Control ' + escape(control) + '.') if control else ''} Full data: {escape(csv_name)}.</p>")
        out.append(_table(columns, rows) if rows else "<p>None.</p>")
    if info.get("warnings"):
        out.append("<h2>Warnings</h2><ul>" + "".join(f"<li>{escape(w)}</li>" for w in info["warnings"]) + "</ul>")
    if info.get("known_limitations"):
        out.append("<h2>Known limitations</h2><ul>" + "".join(f"<li>{escape(k)}</li>" for k in info["known_limitations"]) + "</ul>")
    out.append("</main></body></html>\n")
    return "".join(out)
