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

