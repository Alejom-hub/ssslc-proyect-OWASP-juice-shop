import json
import os
from flask import Flask, render_template

app = Flask(__name__)

def calculate_risk(result):
    """Calcula un puntaje de riesgo de 1 a 27 basado en metadatos."""
    metadata = result['extra'].get('metadata', {})
    weights = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "ERROR": 3, "WARNING": 2, "INFO": 1}
    
    conf = weights.get(metadata.get('confidence', 'LOW'), 1)
    like = weights.get(metadata.get('likelihood', 'LOW'), 1)
    imp  = weights.get(metadata.get('impact', 'LOW'), 1)
    
    return conf * like * imp

def get_stride_category(check_id):
    """Mapea el ID de la regla a una categoría de STRIDE."""
    cid = check_id.lower()
    if any(k in cid for k in ['auth', 'jwt', 'session']): return "S"
    if any(k in cid for k in ['injection', 'xss', 'sqli']): return "T"
    if any(k in cid for k in ['audit', 'log']): return "R"
    if any(k in cid for k in ['secret', 'hardcode', 'crypto']): return "I"
    if any(k in cid for k in ['dos', 'timeout', 'overflow']): return "D"
    if any(k in cid for k in ['eval', 'rbac', 'permission']): return "E"
    return "I"

def load_semgrep_results():
    # Asegúrate de que estos nombres de archivos sean los correctos en tu carpeta reports/
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
    
    for r in results:
        # 1. Cálculos de Riesgo y STRIDE
        score = calculate_risk(r)
        stride_cat = get_stride_category(r['check_id'])
        
        # 2. Actualizar Estadísticas (Una sola vez para evitar duplicados)
        sev = r['extra'].get('severity', 'INFO')
        results_stats["severity"][sev] = results_stats["severity"].get(sev, 0) + 1
        results_stats["stride"][stride_cat] += 1
        
        # Lógica de Críticas: Score alto O (Severidad Error + Impacto Alto)
        impact = r['extra'].get('metadata', {}).get('impact', 'LOW')
        if score >= 18 or (sev == "ERROR" and impact == "HIGH"):
            results_stats["critical"] += 1
        
        # Contar categorías
        v_class = r['extra'].get('metadata', {}).get('vulnerability_class', ['Otras'])[0]
        results_stats["category"][v_class] = results_stats["category"].get(v_class, 0) + 1

        # 3. Enriquecer objeto
        r['risk_score'] = score
        r['stride_cat'] = stride_cat
        enriched_results.append(r)

    for e in errors:
        lvl = e.get('level', 'unknown')
        errors_stats["level"][lvl] = errors_stats["level"].get(lvl, 0) + 1
        
        etype = e.get('type', 'unknown')[0]
        errors_stats["type"][etype] = errors_stats["type"].get(etype, 0) + 1

    return render_template('dashboard.html', 
                           results=enriched_results, # Usamos la lista con los scores calculados
                           errors=errors, 
                           stats=results_stats, 
                           e_stats=errors_stats)

if __name__ == '__main__':
    app.run(debug=True)