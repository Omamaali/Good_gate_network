from flask import Flask, request, jsonify, abort
from functools import wraps
import secrets

app = Flask(__name__)

# مفتاح المصادقة الأمنية (Security Token)
# ملاحظة: في بيئة الإنتاج، يُفضل تخزين هذا المفتاح داخل متغيرات البيئة (Environment Variables)
API_KEY = "good_gate_secure_token_2026_xyz"

# ==========================================
# 🔒 نظام المصادقة والأمان
# ==========================================
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized Access - Bearer token missing"}), 401
        
        token = auth_header.split(" ")[1]
        # استخدام مقارنة آمنة لتجنب هجمات التوقيت
        if not secrets.compare_digest(token, API_KEY):
            return jsonify({"error": "Unauthorized Access - Invalid token"}), 401
            
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# 🤖 وحدة الذكاء الاصطناعي واكتشاف المخاطر
# ==========================================
def analyze_network_traffic(data):
    """
    تحليل البيانات الواردة باستخدام خوارزميات الذكاء الاصطناعي البسيطة
    لاكتشاف الحالات الشاذة أو المعاملات المشبوهة (AML & Threats).
    """
    threshold = 0.75
    risk_score = 0.1
    
    # المعالجة الذكية وتحليل المخاطر
    if 'tx_amount' in data and data['tx_amount'] > 10000:
        risk_score += 0.4
    if 'geo_location' in data and data['geo_location'] in ['high_risk_zone', 'restricted']:
        risk_score += 0.35
    if 'anomaly_detected' in data and data['anomaly_detected']:
        risk_score += 0.3

    is_malicious = risk_score >= threshold
    
    return {
        "risk_score": round(risk_score, 2),
        "is_malicious": is_malicious,
        "action_taken": "Block (Airlock)" if is_malicious else "Allow"
    }

# ==========================================
# 🌐 المسارات (API Endpoints)
# ==========================================

@app.route('/', methods=['GET'])
def home():
    """المسار الافتراضي للتأكد من عمل الشبكة"""
    return jsonify({
        "system": "GoodGate Network System",
        "status": "Active",
        "security_layer": "Enabled",
        "version": "1.0.0"
    }), 200

@app.route('/api/v1/analyze', methods=['POST'])
@require_api_key
def analyze_data():
    """مسار آمن لاستقبال البيانات وتحليلها بالذكاء الاصطناعي"""
    if not request.json:
        return jsonify({"error": "Invalid payload format, JSON is required"}), 400
        
    req_data = request.json
    
    # تشغيل المنظومة التحليلية
    analysis_report = analyze_network_traffic(req_data)
    
    return jsonify({
        "message": "Analysis completed successfully",
        "timestamp": "2026-05-04T03:20:00Z",
        "security_report": analysis_report
    }), 200

@app.route('/api/v1/status', methods=['GET'])
@require_api_key
def get_status():
    """مسار آمن لعرض حالة العقد (Nodes) والتشفير"""
    return jsonify({
        "node_status": "Online",
        "active_nodes": 4,
        "encryption_protocol": "AES-256-GCM",
        "node_integrity": "Verified"
    }), 200

# ==========================================
# 🚀 تشغيل التطبيق
# ==========================================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 
    import os
import logging
from flask import Flask, jsonify, request, render_template_string
from functools import wraps
from datetime import datetime

# Initialize App
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secure_key_2026')
API_KEY = 'good_gate_secure_token_2026_xyz'

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- In-Memory State & Data (Simulation) ---
transactions = [
    {"id": "TX-2026-001", "amount": 15000, "location": "high_risk_zone", "status": "Blocked", "risk_score": 0.85},
    {"id": "TX-2026-002", "amount": 8500, "location": "moderate_zone", "status": "Pending", "risk_score": 0.45},
    {"id": "TX-2026-003", "amount": 2200, "location": "safe_zone", "status": "Approved", "risk_score": 0.12}
]

nodes = [
    {"id": "Node-Alpha-01", "status": "Online", "integrity": "Verified", "encryption": "AES-256-GCM"},
    {"id": "Node-Beta-02", "status": "Online", "integrity": "Verified", "encryption": "AES-256-GCM"},
    {"id": "Node-Gamma-03", "status": "Isolated", "integrity": "Alert", "encryption": "SSL/TLS"},
    {"id": "Node-Delta-04", "status": "Online", "integrity": "Verified", "encryption": "AES-256-GCM"}
]

# --- Security & Decorators ---
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logging.warning("Unauthorized attempt detected: Missing or malformed header.")
            return jsonify({"error": "Unauthorized access - Header missing"}), 401
        
        token = auth_header.split(" ")[1]
        if token != API_KEY:
            logging.warning("Unauthorized attempt detected: Invalid Token.")
            return jsonify({"error": "Unauthorized access - Invalid token"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# --- API Routes ---
@app.route('/api/v1/status', methods=['GET'])
@require_api_key
def system_status():
    logging.info("System status checked by authorized client.")
    return jsonify({
        "status": "Active",
        "system": "GoodGate Network System",
        "version": "1.0.0",
        "total_nodes": len(nodes),
        "active_nodes": len([n for n in nodes if n['status'] == "Online"]),
        "nodes": nodes,
        "encryption_protocol": "AES-256-GCM",
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/api/v1/transactions', methods=['GET'])
@require_api_key
def get_transactions():
    return jsonify({"transactions": transactions}), 200

@app.route('/api/v1/override/<tx_id>', methods=['POST'])
@require_api_key
def override_transaction(tx_id):
    for tx in transactions:
        if tx["id"] == tx_id:
            tx["status"] = "Approved (Overridden)"
            logging.info(f"Transaction {tx_id} status modified to Override & Allow.")
            return jsonify({
                "message": f"تم تجاوز المنع والسماح بالعملية {tx_id} بنجاح",
                "action_taken": "Override & Allow",
                "tx_id": tx_id
            }), 200
    
    return jsonify({"error": "Transaction not found"}), 404

# --- Dashboard Section (Added to the end of the file) ---
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>GoodGate Network - لوحة التحكم المتقدمة</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; margin: 0; padding: 20px; }
        .container { max-width: 1000px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 6px 20px rgba(0,0,0,0.08); }
        h1 { color: #2c3e50; text-align: center; margin-bottom: 25px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .card { background: #e9f4ff; padding: 15px; border-radius: 8px; text-align: center; border-left: 5px solid #007bff; }
        .card h3 { margin: 0; color: #333; font-size: 1.1em; }
        .card p { margin: 10px 0 0; font-size: 1.5em; font-weight: bold; color: #007bff; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 14px 18px; text-align: right; border-bottom: 1px solid #e9ecef; }
        th { background-color: #2c3e50; color: white; }
        .badge { padding: 6px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }
        .badge-danger { background-color: #f8d7da; color: #721c24; }
        .badge-warning { background-color: #fff3cd; color: #856404; }
        .badge-success { background-color: #d4edda; color: #155724; }
        .btn-action { background-color: #28a745; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; transition: 0.2s; }
        .btn-action:hover { background-color: #218838; }
        .nodes-section { margin-top: 30px; padding: 20px; background: #fdfdfd; border: 1px solid #eee; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ GoodGate Network - لوحة التحكم المتقدمة</h1>
        
        <div class="stats-grid">
            <div class="card">
                <h3>العقد النشطة</h3>
                <p>3 من 4</p>
            </div>
            <div class="card">
                <h3>المعاملات</h3>
                <p>3</p>
            </div>
            <div class="card">
                <h3>حالة الشبكة</h3>
                <p style="color: #28a745;">مستقرة</p>
            </div>
        </div>

        <h2>سجل المعاملات</h2>
        <table>
            <thead>
                <tr>
                    <th>المعرف</th>
                    <th>المبلغ</th>
                    <th>الموقع</th>
                    <th>مستوى الخطورة</th>
                    <th>الحالة</th>
                    <th>الإجراء</th>
                </tr>
            </thead>
            <tbody>
                {% for tx in transactions %}
                <tr>
                    <td>{{ tx.id }}</td>
                    <td>{{ tx.amount }}</td>
                    <td>{{ tx.location }}</td>
                    <td>{{ tx.risk_score }}</td>
                    <td>
                        {% if tx.status == 'Blocked' %}
                            <span class="badge badge-danger">{{ tx.status }}</span>
                        {% elif tx.status == 'Pending' %}
                            <span class="badge badge-warning">{{ tx.status }}</span>
                        {% else %}
                            <span class="badge badge-success">{{ tx.status }}</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if tx.status == 'Blocked' %}
                            <button class="btn-action" onclick="override('{{ tx.id }}')">سماح (Allow)</button>
                        {% else %}
                            -
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <div class="nodes-section">
            <h2>حالة العقد (Nodes)</h2>
            <ul>
                {% for node in nodes %}
                <li><strong>{{ node.id }}:</strong> {{ node.status }} | التكامل: {{ node.integrity }} | التشفير: {{ node.encryption }}</li>
                {% endfor %}
            </ul>
        </div>
    </div>

    <script>
        function override(txId) {
            fetch('/api/v1/override/' + txId, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer good_gate_secure_token_2026_xyz'
                },
                body: JSON.stringify({tx_id: txId})
            })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                location.reload();
            })
            .catch(error => alert('حدث خطأ أثناء تنفيذ الإجراء.'));
        }
    </script>
</body>
</html>
"""

@app.route('/dashboard')
def dashboard():
    return render_template_string(DASHBOARD_HTML, transactions=transactions, nodes=nodes)

# --- App Execution ---
if __name__ == '__main__':
    app.run(port=5000, debug=True)


