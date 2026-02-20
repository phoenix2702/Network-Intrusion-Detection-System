import pyshark

def analyze_snort_alert(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                print(line.strip())  # Print each line of the alert
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
    except UnicodeDecodeError:
        print("Error: Could not decode file. Check the file encoding.")

# Example usage


# Example usage
file_path = "C:/Snort/log/snort.alert"  # Update this path if necessary
analyze_snort_alert(file_path)
