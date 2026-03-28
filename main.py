import asyncio
import logging
import time
from meshtastic_socket import MeshtasticSocket

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def main():
    # Placeholder IP - user needs to change this to their Meshtastic device IP
    hostname = "10.1.5.3"
    
    # Optional: specify a channel name (e.g. 'LongFast' or your custom channel)
    # If None, it will listen to all received channels, and send on channel index 0.
    channel = "jacomms"
    
    print("--- Meshtastic Socket Example ---")
    print(f"Connecting to {hostname} ...")
    
    sock = MeshtasticSocket(hostname=hostname, channel_name=channel)
    
    try:
        await sock.connect()
        print("Successfully connected!")
        
        # Example 1: Send a message without retry/ack
        text_to_send1 = "Hello from async meshtastic-net!"
        print(f"Sending (no ack): '{text_to_send1}'")
        await sock.send_text(text_to_send1)
        
        # Example 2: Send a message WITH retry/ack
        text_to_send2 = "Important text with reliable delivery!"
        print(f"Sending (with ack/retry): '{text_to_send2}'")
        try:
            await sock.send_text(text_to_send2, retry_count=2, ack_timeout=10.0)
            print("Message was acknowledged by the mesh!")
        except Exception as retry_err:
            print(f"Reliable send failed: {retry_err}")
        
        # Example 3: Wait for a message with timeout
        print("Waiting up to 10 seconds for a response...")
        msg = await sock.recv(timeout=10.0)
        
        if msg:
            print(f"Received message from {msg['sender']}: {msg['text']}")
        else:
            print("No message received within timeout.")
            
        # Example 4: Polling loop using has_data
        print("Polling for 5 seconds...")
        for _ in range(5):
            if sock.has_data():
                m = await sock.recv(timeout=0.1)
                if m:
                    print(f"Polled message: {m['text']}")
            else:
                print(".", end="", flush=True)
            await asyncio.sleep(1)
        print("\nFinished polling.")

    except Exception as e: # fallback since underlying library exceptions vary
        print(f"Exception: {e}")
        print("Make sure your device IP is reachable and the channel exists.")
    finally:
        sock.close()
        print("Socket closed.")

if __name__ == "__main__":
    asyncio.run(main())
