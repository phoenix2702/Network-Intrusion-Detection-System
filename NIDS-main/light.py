import requests

# Define the file path and API URL
file_path = "C:/Users/Admin/Downloads/alerts (4).xlsx"  # Use your file path
url = "https://node.lighthouse.storage/api/v0/add"  # API endpoint
api_key = 'b5de18b3.348115dd91d349e99e1f9111efee9b5f'  # Replace with your API key

# Open the file and send a POST request
headers = {
    "Authorization": f"Bearer {api_key}"
}

try:
    with open(file_path, "rb") as file:
        files = {'file': file}
        response = requests.post(url, headers=headers, files=files)
    
    # Check response
    if response.status_code == 200:
        print("File uploaded successfully!")
        print("Response:", response.json())  # Assuming JSON response
    else:
        print(f"Failed to upload file. Status code: {response.status_code}")
        print("Response:", response.text)
except FileNotFoundError:
    print("Error: File not found at specified path.")
except Exception as e:
    print(f"An error occurred: {e}")
