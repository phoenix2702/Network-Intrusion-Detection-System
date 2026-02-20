from flask import Flask, jsonify, render_template
import subprocess
import os

app = Flask(__name__)
capture_process = None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capture_process
    if capture_process is None:
        os.chdir("C:/Snort/bin")
        capture_process = subprocess.Popen([
            "snort.exe", 
            "-i", "4", 
            "-v", 
            "-c", "C:\\Snort\\etc\\snort.conf", 
            "-l", "C:\\Snort\\log", 
            "-A", "fast"
        ])
        return jsonify(status="Capture Started")
    else:
        return jsonify(status="Already Running")

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global capture_process
    if capture_process is not None:
        capture_process.terminate()
        capture_process = None
        return jsonify(status="Capture Stopped")
    else:
        return jsonify(status="No Capture to Stop")

@app.route('/fetch_alerts', methods=['GET'])
def fetch_alerts():
    alerts_file_path = "C:/Snort/log/alert.ids"  # Adjust path as necessary
    try:
        with open(alerts_file_path, 'r') as f:
            alerts = f.readlines()
        return jsonify(alerts=alerts)
    except Exception as e:
        return jsonify(error=str(e)), 500

if __name__ == '__main__':
    app.run(debug=True)
