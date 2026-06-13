from flask import Flask, render_template, request, jsonify
from utils.detector import analyze_url
from utils.history import (
    initialize_database,
    save_scan,
    get_all_scans,
    get_statistics,
    clear_history
)

app = Flask(__name__)


# ==========================
# HOME PAGE
# ==========================

@app.route("/")
def home():
    return render_template("index.html")


# ==========================
# URL SCAN API
# ==========================

@app.route("/scan", methods=["POST"])
def scan():

    try:

        data = request.get_json()

        url = data.get("url", "").strip()

        if not url:
            return jsonify({
                "success": False,
                "message": "URL is required"
            }), 400

        result = analyze_url(url)
        save_scan(
            url,
            result["score"],
            result["status"]
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


# ==========================
# HEALTH CHECK
# ==========================

@app.route("/health")
def health():

    return jsonify({
        "status": "online",
        "project": "Phishing URL Detector"
    })

@app.route("/history")
def history():

    return jsonify(
        get_all_scans()
    )

@app.route("/stats")
def stats():

    return jsonify(
        get_statistics()
    )

@app.route("/clear-history", methods=["DELETE"])
def delete_history():

    clear_history()

    return jsonify({
        "success": True
    })


# ==========================
# ERROR HANDLERS
# ==========================

@app.errorhandler(404)
def page_not_found(error):

    return jsonify({
        "success": False,
        "message": "Page not found"
    }), 404


@app.errorhandler(500)
def internal_server_error(error):

    return jsonify({
        "success": False,
        "message": "Internal server error"
    }), 500


# ==========================
# RUN APPLICATION
# ==========================

if __name__ == "__main__":
    initialize_database()
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )