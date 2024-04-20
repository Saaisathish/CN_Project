from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import joblib
import pandas as pd
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import socket
import threading
import json

app = Flask(__name__)
socketio = SocketIO(app)

# Load the saved model
classifier = joblib.load('model.pkl')

# Generate a random AES key with 16 bytes (128 bits) length
key = b'\x9c\xe5\xac\xe3~\xf5\xfe\x95\x822m]\xf42\xd7\xe7'

# Convert the key to a base64-encoded string for storage or transmission
key_string = base64.b64encode(key).decode('utf-8')

# Define a route to render the input form
@app.route('/')
def index():
    return render_template('index.html')

# Define a TCP server to receive transaction data
def tcp_server():
    HOST = '127.0.0.1'
    PORT = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        print("TCP server started. Listening on port", PORT)

        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print("Received encrypted data:", data.decode())
                # Process the received data
                process_transaction(data.decode())

# Define a function to decrypt the encrypted data
def decrypt_data(encrypted_data, key):
    # Decode the base64-encoded key string
    decoded_key = base64.b64decode(key.encode())
    
    # Create the AES cipher object
    cipher = AES.new(decoded_key, AES.MODE_ECB)
    
    try:
        # Decrypt the data and unpad it
        decrypted_data = unpad(cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size).decode('utf-8')
        print("Decrypted data:", decrypted_data)
        return decrypted_data
    except (ValueError, UnicodeDecodeError) as e:
        print("Error decrypting data:", e)
        return None

# Define a function to process the transaction data
def process_transaction(data):
    print("Processing transaction data...")
    try:
        # Deserialize the received data into a dictionary
        decrypted_data = json.loads(data)
        
        # Decrypt each value in the dictionary
        for key, encrypted_value in decrypted_data.items():
            decrypted_value = decrypt_data(encrypted_value, key_string)
            if decrypted_value is not None:
                decrypted_data[key] = decrypted_value
        
        print("Decrypted transaction data:", decrypted_data)
        
        # Convert the decrypted data to a DataFrame
        input_df = pd.DataFrame([decrypted_data])
        
        # Make prediction
        prediction = classifier.predict(input_df)
        print("Prediction:", prediction)

        # Determine the prediction label
        prediction_label = "Fraudulent transaction" if prediction[0] == 1 else "Not fraudulent transaction"
        
        # Emit the prediction result via Socket.IO
        socketio.emit('prediction_result', {'prediction': prediction_label})
        print("Prediction result emitted:", prediction_label)

    except ValueError as e:
        print("Error processing transaction data:", e)

# Define a Socket.IO event handler for client connection
@socketio.on('connect')
def handle_connect():
    print('Client connected')

# Define a Socket.IO event handler for receiving transaction data
@socketio.on('transaction_data')
def handle_transaction_data(data):
    print("Received transaction data from client:", data)
    
    decrypted_data = {}
    for key, encrypted_value in data.items():
        decrypted_value = decrypt_data(encrypted_value, key_string)
        if decrypted_value is not None:
            decrypted_data[key] = decrypted_value
    
    print("Decrypted transaction data:", decrypted_data)

    # Process the decrypted data
    process_transaction(json.dumps(decrypted_data))

if __name__ == '__main__':
    # Start the TCP server in a separate thread
    tcp_thread = threading.Thread(target=tcp_server)
    tcp_thread.start()
    
    # Run the Flask application with Socket.IO
    socketio.run(app, debug=True)