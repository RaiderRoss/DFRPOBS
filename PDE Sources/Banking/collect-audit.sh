#!/usr/bin/env bash
# ==============================================================
#  Runs ON the research VM. Collects Fineract's command audit
#  trail (m_portfolio_command_source) for one capture window.
#
#    collect-audit.sh <start_utc> <end_utc> <out_dir>
#
#  Writes <out_dir>/audit.jsonl — one command per line, in the
#  order the bank processed them — and prints a JSON summary,
#  including the file's sha256, taken here before the file
#  leaves the machine it was collected on.
#
#  This is the "who" the event stream cannot give: every state-
#  changing API call with its maker (the login that made it),
#  checker, parameters, result and time.
# ==============================================================
set -euo pipefail

start="$1" end="$2" out="$3"
DB="${FINERACT_DB_CONTAINER:-fineract-db-1}"
mkdir -p "$out"

# Sliced on made_on_date_utc, a real timestamptz. made_on_date is the tenant-local
# wall-clock column (Asia/Kolkata on this tenant) and is left empty by this build anyway.
# row_to_json and psql's unaligned tuples-only output give one JSON object per line with
# nothing escaped twice; COPY would re-escape every backslash in the JSON.
docker exec -i "$DB" psql -U postgres -d fineract_default -At -v ON_ERROR_STOP=1 \
	-v start="$start" -v end="$end" > "$out/audit.raw" <<'SQL'
SELECT row_to_json(r) FROM (
  SELECT c.id, c.made_on_date_utc, c.action_name, c.entity_name,
         c.maker_id, mk.username AS maker_username,
         c.checker_id, ck.username AS checker_username, c.checked_on_date_utc,
         c.office_id, c.client_id, c.loan_id, c.savings_account_id,
         c.resource_id, c.subresource_id, c.resource_external_id, c.transaction_id,
         c.api_get_url, c.command_as_json, c.status, c.result_status_code, c.result,
         c.client_ip, c.idempotency_key, c.is_sanitized
  FROM m_portfolio_command_source c
  LEFT JOIN m_appuser mk ON mk.id = c.maker_id
  LEFT JOIN m_appuser ck ON ck.id = c.checker_id
  WHERE c.made_on_date_utc >= :'start'::timestamptz
    AND c.made_on_date_utc <= :'end'::timestamptz
  ORDER BY c.made_on_date_utc, c.id
) r;
SQL

python3 - "$out" <<'PY'
import hashlib, json, os, re, sys

out = sys.argv[1]
# Credential-bearing keys only. Deliberately not "pass": that would take passportNumber,
# which is customer data the investigation may need, not a secret the collector must hide.
SECRET = re.compile(r"password|secret|token", re.I)

def redact(obj):
    hit = False
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if SECRET.search(k) and v not in (None, ""):
                obj[k] = "[redacted by collector]"
                hit = True
            else:
                obj[k], h = redact(v)
                hit = hit or h
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            obj[i], h = redact(v)
            hit = hit or h
    return obj, hit

rows, by_action, makers, redacted = [], {}, {}, 0
with open(os.path.join(out, "audit.raw")) as fh:
    for line in fh:
        if not line.strip():
            continue
        row = json.loads(line)
        row["collector_redacted"] = False
        # command_as_json is the request body as Fineract stored it. It is kept verbatim
        # unless it carries a secret — creating a user stores the new password — in which
        # case the value is replaced and the row says so, rather than altered silently.
        raw = row.get("command_as_json")
        if raw:
            try:
                parsed, hit = redact(json.loads(raw))
                if hit:
                    row["command_as_json"] = json.dumps(parsed)
                    row["collector_redacted"] = True
                    redacted += 1
            except ValueError:
                pass
        key = "%s %s" % (row.get("action_name"), row.get("entity_name"))
        by_action[key] = by_action.get(key, 0) + 1
        m = row.get("maker_username") or "?"
        makers[m] = makers.get(m, 0) + 1
        rows.append(row)

path = os.path.join(out, "audit.jsonl")
with open(path, "w") as fh:
    for row in rows:
        fh.write(json.dumps(row, sort_keys=True) + "\n")
os.remove(os.path.join(out, "audit.raw"))

digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
json.dump({
    "rows": len(rows),
    "by_action": dict(sorted(by_action.items())),
    "by_maker": dict(sorted(makers.items())),
    "redacted_rows": redacted,
    "client_ip_recorded": sum(1 for r in rows if r.get("client_ip")),
    "first_made_on_utc": rows[0]["made_on_date_utc"] if rows else None,
    "last_made_on_utc": rows[-1]["made_on_date_utc"] if rows else None,
    "files": {"audit.jsonl": digest},
}, sys.stdout)
print()
PY
