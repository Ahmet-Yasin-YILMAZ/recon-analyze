#!/bin/bash
set -uo pipefail

read -p "Analiz edilecek klasörün yolu: " SCAN_DIR

if [ -z "$SCAN_DIR" ] || [ ! -d "$SCAN_DIR" ]; then
    echo "[!] Geçerli bir klasör yolu girilmedi: '$SCAN_DIR'"
    exit 1
fi

SCAN_DIR="$(cd "$SCAN_DIR" && pwd)"
TARGET_NAME="$(basename "$SCAN_DIR" | sed 's/^recon_//')"
REPORT="$SCAN_DIR/RECON_REPORT.md"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "[+] '$SCAN_DIR' analiz ediliyor..."

: > "$TMPDIR/subdomains.txt"
: > "$TMPDIR/urls.txt"
: > "$TMPDIR/raw_findings.tsv"
: > "$TMPDIR/other_files.txt"
: > "$TMPDIR/skipped_raw.txt"
: > "$TMPDIR/normalized_endpoints.tsv"

count_lines() {
    if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi
}

count_nonempty() {
    if [ -s "$1" ]; then grep -cve '^[[:space:]]*$' "$1" 2>/dev/null || echo 0; else echo 0; fi
}

severity_base() {
    local sev_lc
    sev_lc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    case "$sev_lc" in
        critical) echo 95 ;;
        high) echo 85 ;;
        medium) echo 65 ;;
        low) echo 40 ;;
        info|informational) echo 15 ;;
        unknown|"") echo 25 ;;
        *) echo 50 ;;
    esac
}

priority_label() {
    local score="$1"
    if [ "$score" -ge 90 ]; then echo "P0"
    elif [ "$score" -ge 75 ]; then echo "P1"
    elif [ "$score" -ge 50 ]; then echo "P2"
    else echo "P3"
    fi
}

canonical_endpoint() {
    local u="$1"
    u="${u%%#*}"
    u="$(printf '%s' "$u" | sed -E 's#^[Hh][Tt][Tt][Pp][Ss]?://##')"
    u="${u%%\?*}"
    u="${u%%\&*}"
    u="${u%%/}"
    printf '%s\n' "$u" | sed -E 's#//+#/#g'
}

extract_param_names() {
    local u="$1"
    if [[ "$u" == *\?* ]]; then
        printf '%s\n' "${u#*\?}" |
        tr '&' '\n' |
        cut -d= -f1 |
        sed '/^[[:space:]]*$/d' |
        sort -u |
        paste -sd, -
    else
        echo ""
    fi
}

url_host() {
    local u="$1"
    printf '%s\n' "$u" |
        sed -E 's#^[Hh][Tt][Tt][Pp][Ss]?://##; s#/.*$##; s#:[0-9]+$##'
}

url_path() {
    local u="$1"
    local x
    x="$(printf '%s\n' "$u" | sed -E 's#^[Hh][Tt][Tt][Pp][Ss]?://##')"
    if [[ "$x" != */* ]]; then
        echo "/"
    else
        echo "/${x#*/}" | sed 's#?.*$##; s#//*#/#g; s#/$##'
    fi
}

url_interest() {
    local u="$1"
    local p
    p="$(printf '%s\n' "$u" | tr '[:upper:]' '[:lower:]')"

    if [[ "$p" =~ (^|[/?._-])(admin|administrator|manage|internal|debug|actuator|swagger|openapi|graphql|api|oauth|authorize|callback|redirect|upload|download|export|import|proxy|render|fetch|webhook|url=|next=|dest=|target=)([/?._=&-]|$) ]]; then
        echo "high"
    elif [[ "$u" == *"?"* ]]; then
        echo "medium"
    else
        echo "low"
    fi
}

add_raw_finding() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >> "$TMPDIR/raw_findings.tsv"
}

file_count=0

while IFS= read -r -d '' f; do
    file_count=$((file_count+1))
    fname="$(basename "$f")"
    fsize="$(wc -c < "$f" 2>/dev/null || echo 0)"
    [ "$fsize" -eq 0 ] && continue

    case "$fname" in
        *raw*.txt|*raw_output*|*progress.log|*.log|katana_raw.jsonl|dnsx_records.json|gowitness_results.jsonl|RECON_REPORT.md)
            echo "$fname (ham/debug veri, atlandı)" >> "$TMPDIR/skipped_raw.txt"
            continue ;;
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*.txt)
            continue ;;
        *.jpg|*.jpeg|*.png|*.gif|*.ico|*.svg|*.avif|*.woff*|*.css|*.js)
            continue ;;
    esac

    case "$fname" in
        subdomains*.txt)
            cat "$f" >> "$TMPDIR/subdomains.txt"
            continue ;;

        gau_filtered.txt|*katana_urls_inscope*)
            cat "$f" >> "$TMPDIR/urls.txt"
            continue ;;

        sqlmap_summary.txt|sqlmap_results.txt)
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                endpoint="$(printf '%s\n' "$line" | grep -oE 'https?://[^ ]+' | head -1)"
                [ -z "$endpoint" ] && endpoint="$TARGET_NAME"
                add_raw_finding 93 92 "SQLi" "high" "SQL injection candidate from sqlmap" "$endpoint" "$fname" "sqlmap produced injection-related evidence." "Inspect the corresponding sqlmap detail output and reproduce the finding manually within authorized scope." "sqli|$(canonical_endpoint "$endpoint")" "strong"
            done < "$f"
            continue ;;

        xsstrike_results.txt)
            while IFS= read -r line; do
                if printf '%s\n' "$line" | grep -qi "URL:"; then
                    endpoint="$(printf '%s\n' "$line" | sed 's/.*URL:[[:space:]]*//' | awk '{print $1}')"
                    [ -z "$endpoint" ] && endpoint="$TARGET_NAME"
                    add_raw_finding 78 82 "XSS" "high" "XSS candidate from XSStrike" "$endpoint" "$fname" "XSStrike reported an XSS-related URL." "Reproduce the exact payload/context in a browser and confirm execution." "xss|$(canonical_endpoint "$endpoint")" "strong"
                fi
            done < "$f"
            continue ;;

        jwt_analysis.txt)
            while IFS= read -r line; do
                if printf '%s\n' "$line" | grep -qiE 'POTANSIYEL IDOR|BAŞARILI|KRİTİK|alg:none'; then
                    add_raw_finding 70 65 "JWT" "medium" "JWT security candidate" "$TARGET_NAME" "$fname" "JWT analysis flagged a potentially security-relevant condition." "Retest authorization with controlled tokens/roles and verify whether access control is actually bypassed." "jwt|$line" "moderate"
                fi
            done < "$f"
            continue ;;

        nuclei_critical_high.txt|nuclei_results.txt)
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                sev="$(printf '%s\n' "$line" | grep -oiE '\[(critical|high|medium|low|info)\]' | head -1 | tr -d '[]')"
                [ -z "$sev" ] && sev="medium"
                base="$(severity_base "$sev")"
                endpoint="$(printf '%s\n' "$line" | grep -oE 'https?://[^ ]+' | head -1)"
                [ -z "$endpoint" ] && endpoint="$TARGET_NAME"
                title="$(printf '%s\n' "$line" | sed 's/^[[:space:]]*//' | cut -c1-180)"

                sev_lc="$(printf '%s' "$sev" | tr '[:upper:]' '[:lower:]')"
                case "$sev_lc" in
                    critical) conf=85; action="Reproduce immediately and verify impact/exploitability within authorized scope." ;;
                    high) conf=78; action="Manually validate the finding, affected endpoint and security impact." ;;
                    medium) conf=65; action="Manually validate the request/response and eliminate framework/version false positives." ;;
                    *) conf=45; action="Review manually and determine whether the result is security-relevant." ;;
                esac

                add_raw_finding "$base" "$conf" "Nuclei" "$sev" "$title" "$endpoint" "$fname" "Nuclei reported a ${sev} severity match." "$action" "nuclei|$sev|$(canonical_endpoint "$endpoint")" "tool"
            done < "$f"
            continue ;;

        nuclei_dast_all.jsonl)
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                printf '%s' "$line" | jq -e . >/dev/null 2>&1 || continue

                sev="$(printf '%s' "$line" | jq -r '.info.severity // "info"')"
                template="$(printf '%s' "$line" | jq -r '.["template-id"] // "unknown-template"')"
                endpoint="$(printf '%s' "$line" | jq -r '.["matched-at"] // .host // "unknown"')"
                name="$(printf '%s' "$line" | jq -r '.info.name // .["template-id"] // "DAST finding"')"
                base="$(severity_base "$sev")"

                sev_lc="$(printf '%s' "$sev" | tr '[:upper:]' '[:lower:]')"
                case "$sev_lc" in
                    critical) conf=82 ;;
                    high) conf=75 ;;
                    medium) conf=60 ;;
                    *) conf=40 ;;
                esac

                add_raw_finding "$base" "$conf" "DAST" "$sev" "$name [$template]" "$endpoint" "$fname" "Nuclei DAST produced a structured match." "Manually reproduce the request/response and confirm exploitability." "dast|$template|$(canonical_endpoint "$endpoint")" "structured"
            done < "$f"
            continue ;;

                thog_swagger|thog_github|*trufflehog*)
            while IFS= read -r line; do
                if printf '%s\n' "$line" | grep -qi "^Found verified result"; then
                    add_raw_finding 99 98 "Secret" "critical" "Verified secret exposure" "$TARGET_NAME" "$fname" "A verified secret was reported." "Confirm validity and impact, then handle/report the exposure responsibly." "secret|verified|$line" "verified"

                elif printf '%s\n' "$line" | grep -qi "^Found unverified result"; then
                    add_raw_finding 38 30 "Secret" "unknown" "Unverified secret candidate" "$TARGET_NAME" "$fname" "A secret-like value was reported but has not been verified." "Inspect the original source and determine whether the value is real and security-relevant." "secret|unverified|$line" "heuristic"
                fi
            done < "$f"
            continue ;;

        ferox_suspicious.txt|ferox_interesting.txt)
            while IFS= read -r line; do
                endpoint="$(printf '%s\n' "$line" | grep -oE 'https?://[^ ]+' | head -1)"
                [ -z "$endpoint" ] && endpoint="$line"

                if printf '%s\n' "$line" | grep -qE 'https?://[^ ]*/\.[a-zA-Z0-9_-]'; then
                    add_raw_finding 58 55 "Dotfile" "unknown" "Hidden/dotfile path candidate" "$endpoint" "$fname" "feroxbuster found a dot-prefixed path candidate." "Request it manually and determine whether sensitive content is exposed." "dotfile|$(canonical_endpoint "$endpoint")" "heuristic"
                elif printf '%s\n' "$endpoint" | grep -qiE '/(admin|administrator|debug|actuator|swagger|openapi|graphql|\.env|\.git|\.htaccess|server-status)(/|$|[?#])'; then
                    add_raw_finding 50 50 "Sensitive path" "unknown" "Potentially sensitive path candidate" "$endpoint" "$fname" "feroxbuster identified a path commonly associated with administrative, diagnostic or configuration interfaces." "Request it manually, determine authentication requirements and inspect whether sensitive information or privileged functionality is exposed." "ferox-sensitive|$(canonical_endpoint "$endpoint")" "heuristic"
                elif printf '%s\n' "$endpoint" | grep -qiE '/[^ ]+\.(bak|backup|old|orig|swp|sql|conf|config|yml|yaml|ini|log|dump)([?#]|$)'; then
                    add_raw_finding 50 50 "Backup/config artifact" "unknown" "Potential backup or configuration artifact" "$endpoint" "$fname" "feroxbuster identified a file extension associated with backups, configuration or logs." "Request it manually and determine whether sensitive content is exposed." "ferox-artifact|$(canonical_endpoint "$endpoint")" "heuristic"
                fi
            done < "$f"
            continue ;;
    esac

    if [[ "$fname" == *.txt ]]; then
        first_line="$(head -1 "$f" 2>/dev/null)"

        if echo "$first_line" | grep -qE "^sqlmap identified the following injection point"; then
            add_raw_finding 93 92 "SQLi" "high" "SQL injection candidate" "$TARGET_NAME" "$fname" "sqlmap injection-point marker detected." "Inspect the sqlmap detail output and reproduce manually." "sqli|$fname" "strong"
        elif head -5 "$f" 2>/dev/null | grep -qE "^Efficiency: 100$"; then
            add_raw_finding 78 82 "XSS" "high" "XSS candidate" "$TARGET_NAME" "$fname" "XSStrike success marker detected." "Inspect the exact payload and reproduce in a browser." "xss|$fname" "strong"
        elif echo "$first_line" | grep -qE "^https?://"; then
            cat "$f" >> "$TMPDIR/urls.txt"
        elif echo "$first_line" | grep -qE "^[a-zA-Z0-9](-?[a-zA-Z0-9])*(\.[a-zA-Z0-9](-?[a-zA-Z0-9])*)+$"; then
            cat "$f" >> "$TMPDIR/subdomains.txt"
        else
            echo "$fname" >> "$TMPDIR/other_files.txt"
        fi
    else
        echo "$fname" >> "$TMPDIR/other_files.txt"
    fi
done < <(find "$SCAN_DIR" -type f -print0)

sort -u "$TMPDIR/urls.txt" -o "$TMPDIR/urls.txt" 2>/dev/null || true
sort -u "$TMPDIR/subdomains.txt" -o "$TMPDIR/subdomains.txt" 2>/dev/null || true

awk '
function lower(s) { return tolower(s) }
function strip_scheme(s) {
    sub(/^[Hh][Tt][Tt][Pp][Ss]?:\/\//, "", s)
    return s
}
function canonical(s, x) {
    x=s
    sub(/#.*/, "", x)
    x=strip_scheme(x)
    sub(/\?.*/, "", x)
    sub(/\/$/, "", x)
    gsub(/\/+/, "/", x)
    return x
}
function host(s, x) {
    x=strip_scheme(s)
    sub(/\/.*/, "", x)
    sub(/:[0-9]+$/, "", x)
    return x
}
function path(s, x) {
    x=strip_scheme(s)
    if (x !~ /\//) return "/"
    sub(/^[^\/]*/, "", x)
    sub(/\?.*/, "", x)
    gsub(/\/+/, "/", x)
    sub(/\/$/, "", x)
    return x
}
function params(s, x,n,a,i,k,v,out) {
    out=""
    if (s !~ /\?/) return out
    x=s
    sub(/^.*\?/, "", x)
    n=split(x,a,"&")
    for (i=1;i<=n;i++) {
        k=a[i]
        sub(/=.*/, "", k)
        if (k!="") {
            if (!(k in seen_param)) {
                seen_param[k]=1
                if (out!="") out=out ","
                out=out k
            }
        }
    }
    delete seen_param
    return out
}
function interest(s, x) {
    x=tolower(s)
    if (x ~ /(admin|administrator|manage|internal|debug|actuator|swagger|openapi|graphql|api|oauth|authorize|callback|redirect|upload|download|export|import|proxy|render|fetch|webhook|url=|next=|dest=|target=)/)
        return "high"
    if (s ~ /\?/) return "medium"
    return "low"
}
{
    c=canonical($0)
    param_names=params($0)
    i=interest($0)
    printf "%s\t%s\t%s\t%s\t%s\n", c, host($0), path($0), param_names, i
}
' "$TMPDIR/urls.txt" | sort -u > "$TMPDIR/normalized_endpoints.tsv"

FILE_COUNT="$file_count"
URL_COUNT="$(count_lines "$TMPDIR/urls.txt")"
CANON_URL_COUNT="$(cut -f1 "$TMPDIR/normalized_endpoints.tsv" | sort -u | wc -l | tr -d ' ')"
ENDPOINT_COUNT="$(awk -F '\t' '{print $2 "\t" $3}' "$TMPDIR/normalized_endpoints.tsv" | sort -u | wc -l | tr -d ' ')"
SKIPPED_COUNT="$(count_lines "$TMPDIR/skipped_raw.txt")"
UNCLASSIFIED_COUNT="$(count_lines "$TMPDIR/other_files.txt")"

awk -F '\t' -v target="$TARGET_NAME" '
function target_host(s, x) {
    x=s
    sub(/^https?:\/\//,"",x)
    sub(/\/.*/,"",x)
    sub(/:[0-9]+$/,"",x)
    return tolower(x)
}
function in_scope_host(h, t) {
    h=tolower(h)
    t=tolower(t)
    if (h==t) return 1
    if (h ~ ("\\." t "$")) return 1
    return 0
}
function fetch_path(p) {
    p=tolower(p)
    if (p ~ /^\/wp-json\/oembed\/1\.0\/(embed|proxy)\/?$/) return 1
    if (p ~ /^\/wp-json\/redirection\/v1\/redirect\/?$/) return 1
    if (p ~ /(^|\/)(redirect|redirects|callback|proxy|fetch|webhook)(\/|$)/) return 1
    return 0
}
{
    canon=$1
    host=$2
    path=$3
    param=$4

    if (!in_scope_host(host, target)) next
    if (!fetch_path(path)) next
    if (param=="") next

    suspicious=0
    n=split(param, parts, ",")
    for (i=1; i<=n; i++) {
        param_name=tolower(parts[i])
        if (param_name=="url" || param_name=="uri" || param_name=="target" || param_name=="dest" || param_name=="destination" || param_name=="redirect" || param_name=="redirect_uri" || param_name=="redirect_url" || param_name=="next" || param_name=="return" || param_name=="return_url" || param_name=="returnto" || param_name=="continue" || param_name=="callback" || param_name=="callback_url" || param_name=="webhook" || param_name=="endpoint" || param_name=="proxy" || param_name=="fetch" || param_name=="resource" || param_name=="file" || param_name=="path" || param_name=="template")
            suspicious=1
    }

    if (suspicious) {
        group="heuristic-fetch|" canon "|" param
        if (!(group in seen)) {
            seen[group]=1
            print "42\t25\tServer-side fetch/redirect candidate\tunknown\tPotential server-side fetch or redirect parameter\t" canon "\tURL heuristic\tAn in-scope endpoint associated with server-side fetching or redirects exposes a parameter commonly used for destination or callback control; this is only a candidate.\tValidate the parameter behavior manually with an authorized controlled test. The parameter name and endpoint pattern alone do not prove SSRF or open redirect.\t" group "\theuristic"
        }
    }
}
' "$TMPDIR/normalized_endpoints.tsv" > "$TMPDIR/heuristics.tsv"


cat "$TMPDIR/raw_findings.tsv" "$TMPDIR/heuristics.tsv" > "$TMPDIR/all_findings.tsv"

awk -F '\t' '
function norm_endpoint(s,x) {
    x=s
    sub(/^https?:\/\//,"",x)
    sub(/#.*/,"",x)
    sub(/\?.*/,"",x)
    sub(/^www\./,"",x)
    sub(/\/+$/,"",x)
    return tolower(x)
}
function hostpart(s,x) {
    x=s
    sub(/^https?:\/\//,"",x)
    sub(/\/.*/,"",x)
    sub(/:[0-9]+$/,"",x)
    return tolower(x)
}
function tool_name(s) {
    if (s ~ /^ferox_/) return "feroxbuster"
    if (s ~ /^nuclei_dast/) return "nuclei-dast"
    if (s ~ /^nuclei_/) return "nuclei"
    if (s ~ /^sqlmap_/) return "sqlmap"
    if (s ~ /^xsstrike_/) return "xsstrike"
    if (s ~ /^thog_|trufflehog/) return "trufflehog"
    if (s ~ /^jwt_/) return "jwt-module"
    return s
}
function family(cat,title,x) {
    x=tolower(cat " " title)
    if (x ~ /secret/) return "secret|" hostpart($6)
    if (x ~ /dotfile/) return "dotfile|" hostpart($6)
    if (x ~ /ssrf|redirect|server-side fetch|proxy/) return "ssrf|" norm_endpoint($6)
    if (x ~ /sqli|sql injection/) return "sqli|" norm_endpoint($6)
    if (x ~ /xss|cross-site scripting/) return "xss|" norm_endpoint($6)
    if (x ~ /jwt/) return "jwt|" norm_endpoint($6)
    if (cat=="Nuclei" || cat=="DAST") return "toolvuln|" cat "|" norm_endpoint($6)
    return "other|" cat "|" norm_endpoint($6)
}
{
    score=$1+0
    conf=$2+0
    cat=$3
    sev=$4
    title=$5
    endpoint=$6
    source=$7
    reason=$8
    action=$9
    g=family(cat,title)

    if (!(g in n)) {
        n[g]=0
        independent[g]=0
        endpoint_n[g]=0
        max_conf[g]=0
        best_sev[g]="unknown"
        best_title[g]=title
        best_reason[g]=reason
        best_action[g]=action
        cats[g]=cat
        sources[g]=""
        endpoints[g]=""
    }

    n[g]++

    sk=g "|" tool_name(source)
    if (!(sk in source_seen)) {
        source_seen[sk]=1
        independent[g]++
    }

    ek=g "|" norm_endpoint(endpoint)
    if (!(ek in endpoint_seen)) {
        endpoint_seen[ek]=1
        endpoint_n[g]++
    }

    if (conf > max_conf[g]) max_conf[g]=conf

    if (sources[g]=="") sources[g]=source
    else if (index("," sources[g] ",", "," source ",") == 0) sources[g]=sources[g] "," source

    ep=norm_endpoint(endpoint)
    if (endpoints[g]=="") endpoints[g]=ep
    else if (index("|" endpoints[g] "|", "|" ep "|") == 0) endpoints[g]=endpoints[g] "|" ep

    if (sev=="critical") best_sev[g]="critical"
    else if (sev=="high" && best_sev[g]!="critical") best_sev[g]="high"
    else if (sev=="medium" && best_sev[g]!="critical" && best_sev[g]!="high") best_sev[g]="medium"
}
END {
    for (g in n) {
        impact=0
        exploit=0
        exposure=10
        penalty=0

        if (g ~ /^secret\|/) {
            impact=30
            exploit=10
            penalty=20
        } else if (g ~ /^dotfile\|/) {
            impact=15
            exploit=10
            penalty=5
        } else if (g ~ /^ssrf\|/) {
            impact=30
            exploit=20
            penalty=15
        } else if (g ~ /^sqli\|/) {
            impact=40
            exploit=30
        } else if (g ~ /^xss\|/) {
            impact=25
            exploit=25
        } else if (g ~ /^jwt\|/) {
            impact=35
            exploit=20
        } else if (g ~ /^toolvuln\|/) {
            if (best_sev[g]=="critical") { impact=40; exploit=30 }
            else if (best_sev[g]=="high") { impact=32; exploit=24 }
            else if (best_sev[g]=="medium") { impact=20; exploit=14 }
            else { impact=10; exploit=6 }
        }

        evidence=0
        if (independent[g]>=1) evidence+=10
        if (independent[g]>=2) evidence+=15
        if (independent[g]>=3) evidence+=10

        correlation=0
        if (independent[g]>=2) correlation=10
        if (independent[g]>=3) correlation=15

        if (g ~ /^secret\|/ && independent[g]==1) {
            evidence=8
            correlation=0
        }

        if (g ~ /^ssrf\|/ && independent[g]==1) {
            evidence=5
            correlation=0
        }

        risk=impact+exploit+exposure+evidence+correlation-penalty

        if (max_conf[g]>=70) risk+=10
        else if (max_conf[g]>=50) risk+=5
        else if (max_conf[g]<30) risk-=5

        if (risk>100) risk=100
        if (risk<1) risk=1

        if (risk>=90) priority="P0"
        else if (risk>=75) priority="P1"
        else if (risk>=50) priority="P2"
        else priority="P3"

        if (independent[g]>=2) status="CORRELATED"
        else if (g ~ /^dotfile\|/ || g ~ /^ssrf\|/) status="NEEDS_MANUAL_VALIDATION"
        else status="SUSPECTED"

        if (g ~ /^secret\|/) {
            decision="Potential secret exposure"
            next_action="Inspect the original evidence, identify each secret-like value, determine whether it is a real credential or false positive, and verify security relevance."
        } else if (g ~ /^dotfile\|/) {
            decision="Hidden dotfile exposure candidate"
            next_action="Request each affected path and record status code, content type, body size and whether sensitive content is exposed."
        } else if (g ~ /^ssrf\|/) {
            decision="Potential server-side fetch/redirect candidate"
            next_action="Identify the controlling parameter and validate server-side fetch or redirect behavior with an authorized controlled test."
        } else {
            decision=best_title[g]
            next_action=best_action[g]
        }

        print risk "\t" priority "\t" max_conf[g] "\t" status "\t" best_sev[g] "\t" cats[g] "\t" n[g] "\t" independent[g] "\t" endpoint_n[g] "\t" decision "\t" endpoints[g] "\t" sources[g] "\t" next_action "\t" impact "\t" exploit "\t" exposure "\t" evidence "\t" correlation "\t" penalty "\t" best_reason[g]
    }
}
' "$TMPDIR/all_findings.tsv" | sort -t $'\t' -k1,1nr -k3,3nr > "$TMPDIR/evidence_findings.tsv"

FINDING_COUNT="$(wc -l < "$TMPDIR/evidence_findings.tsv" | tr -d ' ')"
P0_COUNT="$(awk -F '\t' '$2=="P0"{n++} END{print n+0}' "$TMPDIR/evidence_findings.tsv")"
P1_COUNT="$(awk -F '\t' '$2=="P1"{n++} END{print n+0}' "$TMPDIR/evidence_findings.tsv")"
P2_COUNT="$(awk -F '\t' '$2=="P2"{n++} END{print n+0}' "$TMPDIR/evidence_findings.tsv")"
P3_COUNT="$(awk -F '\t' '$2=="P3"{n++} END{print n+0}' "$TMPDIR/evidence_findings.tsv")"
CRITICAL_COUNT="$(awk -F '\t' '$5=="critical"{n++} END{print n+0}' "$TMPDIR/evidence_findings.tsv")"
HIGH_COUNT="$(awk -F '\t' '$5=="high"{n++} END{print n+0}' "$TMPDIR/evidence_findings.tsv")"
MEDIUM_COUNT="$(awk -F '\t' '$5=="medium"{n++} END{print n+0}' "$TMPDIR/evidence_findings.tsv")"
HEURISTIC_COUNT="$(awk -F '\t' '$5=="unknown"{n++} END{print n+0}' "$TMPDIR/evidence_findings.tsv")"

cat > "$REPORT" <<EOF
_Hedef: ${TARGET_NAME}_
_Klasör: ${SCAN_DIR}_
_Oluşturulma: $(date '+%Y-%m-%d %H:%M')_

> v3.4; evidence quality, independent-source correlation, confidence, impact, exploitability ve false-positive penalty ayrı hesaplanır. Heuristic ve suspected bulgular doğrulanmış zafiyet değildir.


| Metrik | Değer |
|---|---:|
| Taranan toplam dosya | $FILE_COUNT |
| Ham URL kaydı | $URL_COUNT |
| Canonical URL | $CANON_URL_COUNT |
| Canonical endpoint kaydı | $ENDPOINT_COUNT |
| Correlated finding | $FINDING_COUNT |
| P0 | $P0_COUNT |
| P1 | $P1_COUNT |
| P2 | $P2_COUNT |
| P3 | $P3_COUNT |
| Critical | $CRITICAL_COUNT |
| High | $HIGH_COUNT |
| Medium | $MEDIUM_COUNT |
| Unknown / heuristic | $HEURISTIC_COUNT |
| Atlanan ham/debug dosya | $SKIPPED_COUNT |
| Sınıflandırılamayan dosya | $UNCLASSIFIED_COUNT |


\`\`\`text
Recon files
    ↓
Normalization
    ↓
Evidence extraction
    ↓
Finding family grouping
    ↓
Independent-source correlation
    ↓
Confidence
    ↓
Impact
    ↓
Exploitability
    ↓
Exposure
    ↓
False-positive penalty
    ↓
Risk score
    ↓
Decision / next action
\`\`\`


Confidence, kanıt gücünü; risk ise bulgu doğruysa potansiyel etki, exploitability ve exposure'ı gösterir. Düşük confidence ile yüksek impact aynı finding'de birlikte bulunabilir.


| Bileşen | Açıklama |
|---|---|
| Impact | Bulgu doğruysa potansiyel etki |
| Exploitability | İstismar edilebilirlik sinyali |
| Exposure | Internet-facing erişilebilirlik sinyali |
| Evidence strength | Kanıtın gücü |
| Correlation bonus | Bağımsız kaynakların desteği |
| False-positive penalty | Heuristic yanlış pozitif riski |

| Skor | Öncelik |
|---:|:---:|
| 90–100 | P0 |
| 75–89 | P1 |
| 50–74 | P2 |
| 1–49 | P3 |


| # | Skor | Öncelik | Güven | Status | Severity | Kategori | Evidence | Bağımsız kaynak | Endpoint | Karar |
|---:|---:|:---:|---:|---|---|---|---:|---:|---:|---|
EOF

awk -F '\t' '{
    printf "| %d | %s | %s | %s%% | %s | %s | %s | %s | %s | %s | %s |\n", NR,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10
}' "$TMPDIR/evidence_findings.tsv" >> "$REPORT"

cat >> "$REPORT" <<'EOF'


EOF

awk -F '\t' '{
    print "### " NR ". [" $2 " / " $1 "] " $10
    print ""
    print "- **Confidence:** " $3 "%"
    print "- **Status:** " $4
    print "- **Severity:** " $5
    print "- **Categories:** " $6
    print "- **Evidence observations:** " $7
    print "- **Independent sources:** " $8
    print "- **Affected endpoints:** " $9
    print "- **Sources:** " $12
    print "- **Impact if true:** " $14
    print "- **Exploitability:** " $15
    print "- **Exposure:** " $16
    print "- **Evidence strength:** " $17
    print "- **Correlation bonus:** " $18
    print "- **False-positive penalty:** " $19
    print "- **Why:** " $20
    print "- **Next action:** " $13
    print ""
    print "**Etkilenen endpoint listesi:**"
    n_ep=split($11, ep_arr, "|")
    ep_limit=(n_ep>20) ? 20 : n_ep
    for (i=1;i<=ep_limit;i++) print "  - " ep_arr[i]
    if (n_ep>20) print "  - ... ve " (n_ep-20) " tane daha"
    print ""
}' "$TMPDIR/evidence_findings.tsv" >> "$REPORT"

cat >> "$REPORT" <<'EOF'


- Evidence count is not the same as independent evidence.
- Multiple URLs from the same tool do not automatically increase confidence.
- Independent-source correlation increases confidence only when different tools support the same finding family.
- A heuristic parameter name does not prove SSRF, open redirect or another vulnerability.
- Secret-like values from one source remain suspected until inspected and verified.
- Locale/domain variants are grouped under one finding when they represent the same vulnerability family.
- Third-party endpoints are not treated as target findings.
- Static assets and ordinary content-discovery URLs are not security findings by themselves.
- VERIFIED is not assigned automatically without explicit verification evidence.


EOF

if [ -s "$TMPDIR/other_files.txt" ]; then
    echo "## Sınıflandırılamayan dosyalar" >> "$REPORT"
    echo "" >> "$REPORT"
    sort -u "$TMPDIR/other_files.txt" | sed 's/^/- /' >> "$REPORT"
fi

cat >> "$REPORT" <<'EOF'


EOF

if [ -s "$TMPDIR/skipped_raw.txt" ]; then
    echo "## Atlanan ham/debug dosyalar" >> "$REPORT"
    echo "" >> "$REPORT"
    sort -u "$TMPDIR/skipped_raw.txt" | sed 's/^/- /' >> "$REPORT"
fi

echo ""
echo "[+] Rapor hazır: $REPORT"
echo "============================================================"
head -160 "$REPORT"