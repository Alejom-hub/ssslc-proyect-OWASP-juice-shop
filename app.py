import json
import os
from flask import Flask, render_template

app = Flask(__name__)

STRIDE_LABELS = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Privilege Escalation"
}

# Static threat detail data per vulnerability (DREAD: R, E, DI, D, A)
THREAT_DETAILS = {
    "sequelize-injection": {
        "short_name": "SQL INJECTION",
        "stride_cat": "S",
        "description": "Attacker bypasses authentication via SQL injection in the login endpoint",
        "target": "User authentication process — routes/login.ts line 34",
        "attack": "Attacker sends ' OR 1=1-- as email input. The unsanitized query returns the first user in the database — typically the administrator — granting full access without credentials",
        "countermeasures": "Replace string concatenation with parameterized queries using Sequelize replacements. Validate and sanitize all user input before reaching the database layer",
        "dread": {"R": 3, "E": 3, "DI": 2, "D": 3, "A": 3},
        "probability": "HIGH",
        "impact_level": "HIGH"
    },
    "jwt-hardcode": {
        "short_name": "JWT SECRET",
        "stride_cat": "T",
        "description": "Attacker forges session tokens using the hardcoded JWT secret exposed in source code",
        "target": "Session management and token validation — lib/insecurity.ts line 56",
        "attack": 'Attacker reads the hardcoded secret from the public GitHub repository. Using a JWT library, they modify the token payload — changing "role": "customer" to "role": "admin" — and re-sign it with the known secret. The server accepts the forged token as valid',
        "countermeasures": "Store the JWT secret in an environment variable using process.env.JWT_SECRET. Never commit secrets to source control. Rotate the secret immediately and invalidate all existing sessions",
        "dread": {"R": 3, "E": 2, "DI": 3, "D": 2, "A": 3},
        "probability": "MEDIUM",
        "impact_level": "HIGH"
    },
    "code-string-concat": {
        "short_name": "CODE INJECTION",
        "stride_cat": "E",
        "description": "Attacker executes arbitrary server-side code by injecting malicious input into eval() in the user profile endpoint",
        "target": "User profile update process — routes/userProfile.ts line 62",
        "attack": "Attacker sends malicious JavaScript as their username input. The server passes it directly to eval(), which executes it with server-level privileges — a regular user gains full control of the server",
        "countermeasures": "Remove all uses of eval() — it should never receive user-controlled input. Implement strict input validation on all profile fields. Apply the principle of least privilege to limit server process permissions",
        "dread": {"R": 2, "E": 2, "DI": 2, "D": 3, "A": 2},
        "probability": "MEDIUM",
        "impact_level": "MEDIUM"
    }
}


def calculate_dread(dread):
    r, e, di, d, a = dread["R"], dread["E"], dread["DI"], dread["D"], dread["A"]
    return (r + e + di) * (d + a)


def get_risk_level(score):
    if score >= 40:
        return "High"
    elif score >= 25:
        return "Medium"
    return "Low"


def calculate_risk(result):
    metadata = result['extra'].get('metadata', {})
    weights = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "ERROR": 3, "WARNING": 2, "INFO": 1}
    conf = weights.get(metadata.get('confidence', 'LOW'), 1)
    like = weights.get(metadata.get('likelihood', 'LOW'), 1)
    imp  = weights.get(metadata.get('impact', 'LOW'), 1)
    return conf * like * imp


def get_threat_detail(check_id):
    cid = check_id.lower()
    for key, detail in THREAT_DETAILS.items():
        if key in cid:
            return detail
    return None


def get_stride_category(check_id):
    detail = get_threat_detail(check_id)
    if detail:
        return detail["stride_cat"]
    cid = check_id.lower()
    if any(k in cid for k in ['auth', 'jwt', 'session']): return "S"
    if any(k in cid for k in ['injection', 'xss', 'sqli']): return "T"
    if any(k in cid for k in ['audit', 'log']): return "R"
    if any(k in cid for k in ['secret', 'hardcode', 'crypto']): return "I"
    if any(k in cid for k in ['dos', 'timeout', 'overflow']): return "D"
    if any(k in cid for k in ['eval', 'rbac', 'permission']): return "E"
    return "I"


def load_semgrep_results():
    files = ['reports/semgrep-auth-results.json']
    all_results = []
    all_errors = []
    for filename in files:
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    all_results.extend(data.get('results', []))
                    all_errors.extend(data.get('errors', []))
            except json.JSONDecodeError:
                print(f"Error: El archivo {filename} no es un JSON válido.")
    return all_results, all_errors


@app.route('/')
def index():
    results, errors = load_semgrep_results()
    enriched_results = []

    results_stats = {
        "severity": {"ERROR": 0, "WARNING": 0, "INFO": 0},
        "stride": {"S": 0, "T": 0, "R": 0, "I": 0, "D": 0, "E": 0},
        "category": {},
        "total": len(results),
        "critical": 0
    }
    errors_stats = {"level": {}, "type": {}, "total": len(errors)}

    risk_matrix = {
        "HIGH_HIGH": [], "HIGH_MEDIUM": [], "HIGH_LOW": [],
        "MEDIUM_HIGH": [], "MEDIUM_MEDIUM": [], "MEDIUM_LOW": [],
        "LOW_HIGH": [], "LOW_MEDIUM": [], "LOW_LOW": []
    }

    for r in results:
        stride_cat = get_stride_category(r['check_id'])
        threat = get_threat_detail(r['check_id'])

        sev = r['extra'].get('severity', 'INFO')
        results_stats["severity"][sev] = results_stats["severity"].get(sev, 0) + 1
        results_stats["stride"][stride_cat] += 1

        if threat:
            dread = threat["dread"]
            score = calculate_dread(dread)
            prob = threat["probability"]
            imp_level = threat["impact_level"]
            r_sum = dread["R"] + dread["E"] + dread["DI"]
            d_sum = dread["D"] + dread["A"]
            r['risk_score'] = score
            r['risk_level'] = get_risk_level(score)
            r['dread'] = dread
            r['dread_formula'] = f"(R={dread['R']}, E={dread['E']}, DI={dread['DI']}) × (D={dread['D']}, A={dread['A']}) = {r_sum} × {d_sum}"
            r['threat_description'] = threat['description']
            r['threat_target'] = threat['target']
            r['attack_technique'] = threat['attack']
            r['countermeasures'] = threat['countermeasures']
        else:
            score = calculate_risk(r)
            metadata = r['extra'].get('metadata', {})
            prob = metadata.get('likelihood', 'LOW')
            imp_level = metadata.get('impact', 'LOW')
            r['risk_score'] = score
            r['risk_level'] = get_risk_level(score)
            r['dread'] = None
            r['dread_formula'] = None
            r['threat_description'] = r['extra'].get('message', '')
            r['threat_target'] = f"{r['path']} — line {r['start']['line']}"
            r['attack_technique'] = None
            r['countermeasures'] = None

        if r['risk_score'] >= 36 or (sev == "ERROR" and imp_level == "HIGH"):
            results_stats["critical"] += 1

        v_class = r['extra'].get('metadata', {}).get('vulnerability_class', ['Otras'])[0]
        results_stats["category"][v_class] = results_stats["category"].get(v_class, 0) + 1

        short_name = threat["short_name"] if threat else r['check_id'].split('.')[-1].replace('-', ' ').upper()
        matrix_key = f"{prob}_{imp_level}"
        if matrix_key in risk_matrix:
            risk_matrix[matrix_key].append(short_name)

        r['stride_cat'] = stride_cat
        r['stride_label'] = STRIDE_LABELS.get(stride_cat, stride_cat)
        enriched_results.append(r)

    for e in errors:
        lvl = e.get('level', 'unknown')
        errors_stats["level"][lvl] = errors_stats["level"].get(lvl, 0) + 1
        etype = e.get('type', 'unknown')[0]
        errors_stats["type"][etype] = errors_stats["type"].get(etype, 0) + 1

    return render_template('dashboard.html',
                           results=enriched_results,
                           errors=errors,
                           stats=results_stats,
                           e_stats=errors_stats,
                           risk_matrix=risk_matrix)


if __name__ == '__main__':
    app.run(debug=True)
