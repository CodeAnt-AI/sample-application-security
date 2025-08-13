

from flask import Flask, request, jsonify
import requests
import jwt
import yaml

app = Flask(__name__)

# ============================================================================
# API10: Unsafe Consumption of APIs
# ============================================================================

@app.route('/api/weather', methods=['GET'])
def weather_vulnerable():
    # VULNERABLE - No validation of external API response
    # BAD: Trusts external API blindly
    city = request.args.get('city')
    response = requests.get(f'http://external-api.com/weather/{city}')
    data = response.json()  # No validation
    
    # BAD: Direct use in SQL
    query = f"INSERT INTO logs VALUES ('{data['city']}')"  # SQL injection
    db.execute(query)
    
    return jsonify(data)

@app.route('/api/import', methods=['POST'])
def import_vulnerable():
    # VULNERABLE - Unsafe deserialization
    # BAD: Unsafe YAML parsing
    yaml_data = request.data
    config = yaml.load(yaml_data)  # RCE vulnerability!
    return jsonify({"imported": True})