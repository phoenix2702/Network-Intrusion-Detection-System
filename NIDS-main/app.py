from flask import Flask, jsonify, render_template, request, redirect, url_for, send_file
import subprocess
import os
import pandas as pd
import ipaddress
import pickle
import numpy as np
import matplotlib.pyplot as plt

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'  # Set the folder for file uploads
capture_process = None
alerts = []  # Initialize an empty list to store alerts

# Load pre-trained model
model_path = 'final_model.pkl'  # Update to your actual model filename
with open(model_path, 'rb') as model_file:
    model = pickle.load(model_file)

# Utility functions for IP conversion
def convert_ip_to_int(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ValueError:
        return 0

def convert_ip_to_string(ip_int):
    try:
        return str(ipaddress.IPv4Address(ip_int))
    except ValueError:
        return '0'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/capture')
def capture():
    return render_template('capture.html')

@app.route('/alerts')
def alerts_page():
    return render_template('alerts.html')

@app.route('/predictions')
def predictions():
    return render_template('predictions.html')

@app.route('/statistics')
def statistics_page():
    return render_template('statistics.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capture_process
    if capture_process is None:
        os.chdir("C:/Snort/bin")
        capture_process = subprocess.Popen([
            "snort.exe", 
            "-i", "5", 
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
    global alerts
    alerts_file_path = "C:/Snort/log/alert.ids"
    try:
        if not os.path.exists(alerts_file_path):
            return jsonify(error="Alert file not found."), 404

        with open(alerts_file_path, 'r') as f:
            raw_alerts = f.readlines()

        processed_alerts = []
        for alert in raw_alerts:
            parts = alert.split()
            if len(parts) >= 8:
                timestamp = parts[0]
                protocol = "Unknown"
                for proto in ["UDP", "TCP", "ICMP", "SMTP"]:
                    if proto in alert:
                        protocol = proto
                        break
                alert_type = parts[3].strip("[]")
                message = ' '.join(parts[4:]).strip("[]")
                alert_category = "Flood Attack" if "flood" in message.lower() else "Other"

                if '->' in alert:
                    src_ip_port, dest_ip_port = alert.split('->')
                    src_parts = src_ip_port.strip().split()[-1].split(':')
                    dest_parts = dest_ip_port.strip().split()[0].split(':')
                    src_ip, src_port = (src_parts[0], src_parts[1]) if len(src_parts) == 2 else (src_parts[0], 'N/A')
                    dest_ip, dest_port = (dest_parts[0], dest_parts[1]) if len(dest_parts) == 2 else (dest_parts[0], 'N/A')
                else:
                    src_ip, src_port = 'N/A', 'N/A'
                    dest_ip, dest_port = 'N/A', 'N/A'

                processed_alerts.append({
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dest_ip': dest_ip,
                    'protocol': protocol,
                    'type': alert_category,
                    'message': message
                })

        alerts = processed_alerts
        return jsonify(alerts=processed_alerts)

    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/export_alerts')
def export_alerts():
    global alerts
    if not alerts:
        return "No alerts to export!", 400
    df = pd.DataFrame(alerts)
    excel_file_path = "alerts.xlsx"
    df.to_excel(excel_file_path, index=False, engine='openpyxl')
    return send_file(excel_file_path, as_attachment=True)

    
@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('predictions.html', error="No file part in the request")

        file = request.files['file']
        if file.filename == '':
            return render_template('predictions.html', error="No selected file")

        if file:
            # Save the uploaded file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)

            try:
                # Read the uploaded Excel file
                df = pd.read_excel(file_path, engine='openpyxl')  # Use openpyxl explicitly for .xlsx files

                # Define the features required by your model
                features = ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 
                            'L4_SRC_PORT', 'L4_DST_PORT', 
                            'FLOW_DURATION_MILLISECONDS', 'TCP_FLAGS']
                
                # Ensure that the dataframe contains these columns before proceeding
                if not all(feature in df.columns for feature in features):
                    return render_template('predictions.html', error="The uploaded file is missing required columns.")

                # Prepare the input features for prediction
                df_input = df[features]

                # Make predictions using the pre-trained model
                predictions = model.predict(df_input)

                # Add the predictions to the dataframe
                df['Prediction'] = predictions

                # Convert IP addresses back to string format if they are part of the output
                if 'source_ip' in df.columns and 'destination_ip' in df.columns:
                    df['source_ip'] = df['source_ip'].apply(convert_ip_to_string)
                    df['destination_ip'] = df['destination_ip'].apply(convert_ip_to_string)

                # Save the result to a new Excel file
                result_file = os.path.join(app.config['UPLOAD_FOLDER'], 'predictions.xlsx')
                df.to_excel(result_file, index=False)

                # Provide the user with a link to download the result
                return send_file(result_file, as_attachment=True)

            except Exception as e:
                return render_template('predictions.html', error=f"Error processing the file: {str(e)}")

    return redirect(url_for('index'))  # Redirect to home if no file is uploaded or on error




@app.route('/generate_statistics', methods=['GET'])
def generate_statistics():
    try:
        alerts_file_path = "C:/Snort/log/alert.ids"

        if not os.path.exists(alerts_file_path):
            return jsonify(error="Alerts file not found."), 404

        alerts = []
        with open(alerts_file_path, 'r') as f:
            for line in f:
                # Skip empty lines or lines without enough parts
                if not line.strip() or len(line.split()) < 8:
                    print(f"Skipping invalid line: {line.strip()}")
                    continue

                parts = line.split()

                # Parse protocol
                protocol = "Unknown"
                if "UDP" in line:
                    protocol = "UDP"
                elif "TCP" in line:
                    protocol = "TCP"
                elif "ICMP" in line:
                    protocol = "ICMP"
                elif "IPV6-ICMP" in line:
                    protocol = "IPv6-ICMP"

                # Parse alert type (safe indexing with default value)
                alert_type = parts[3].strip("[]") if len(parts) > 3 else "Unknown"

                # Parse priority (safe indexing with default value)
                priority = 0
                try:
                    if "Priority:" in line:
                        priority = int(parts[5].split(":")[1].strip("]"))
                except (IndexError, ValueError):
                    print(f"Priority parsing failed for line: {line.strip()}")

                # Add the parsed data
                alerts.append({"protocol": protocol, "type": alert_type, "priority": priority})

        # Create DataFrame
        df = pd.DataFrame(alerts)

        # If DataFrame is empty, handle gracefully
        if df.empty:
            return jsonify(error="No valid data in the alerts file."), 400

        # Generate statistics
        protocol_counts = df['protocol'].value_counts()
        priority_counts = df['priority'].value_counts()
        alert_type_counts = df['type'].value_counts()

        # Debugging log
        print("Generated statistics:")
        print("Protocol counts:", protocol_counts)
        print("Priority counts:", priority_counts)
        print("Alert type counts:", alert_type_counts)

        # Save charts to static directory
        static_dir = os.path.join(os.path.dirname(__file__), 'static')
        if not os.path.exists(static_dir):
            os.makedirs(static_dir)

        plt.figure(figsize=(10, 6))
        protocol_counts.plot(kind='pie', autopct='%1.1f%%', title='Protocol Distribution', ylabel='')
        plt.savefig(os.path.join(static_dir, 'protocol_distribution.png'))
        plt.close()

        plt.figure(figsize=(10, 6))
        priority_counts.plot(kind='bar', color='skyblue', title='Priority Distribution')
        plt.xlabel('Priority')
        plt.ylabel('Counts')
        plt.savefig(os.path.join(static_dir, 'priority_distribution.png'))
        plt.close()

        plt.figure(figsize=(8, 8))
        alert_type_counts.plot(kind='pie', autopct='%1.1f%%', colors=['orange', 'skyblue', 'green', 'red'], title='Alert Type Distribution')
        plt.ylabel('')
        plt.savefig(os.path.join(static_dir, 'alert_type_counts.png'))
        plt.close()

        return jsonify(status="Statistics generated successfully!")

    except Exception as e:
        print("Error generating statistics:", str(e))
        return jsonify(error="Failed to generate statistics: " + str(e)), 500





if __name__ == '__main__':
    app.run(debug=True)