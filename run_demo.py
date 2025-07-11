def run_demo():
    # Start server
    server = SecureServer()
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(2)  # Give server more time to start
    
    # Test communication
    client = SecureClient()
    messages = [
        "Hello, secure world!",
        "This is a test message",
        "The quick brown fox jumps over the lazy dog"
    ]
    
    for msg in messages:
        print(f"\nSending: {msg}")
        try:
            client.send_message(msg)
        except Exception as e:
            print(f"Error sending message: {str(e)}")
        time.sleep(1)
    
    # Cleanup
    server.stop()
    server_thread.join()
