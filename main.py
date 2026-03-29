import asyncio
import logging
from meshnet.meshtastic_core import Meshtastic

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


async def main():
    mesh = Meshtastic(ip="10.1.5.3")

    try:
        await mesh.connect()
        print("Connected!")

        # --- Channel broadcast ---
        ch = mesh.channel("jacomms")

        print("Sending broadcast (no ack)...")
        await ch.send_text("Hello from async meshtastic-net!")

        print("Sending broadcast (with ack/retry)...")
        try:
            await ch.send_text("Important channel message!", retry_count=2, ack_timeout=10.0)
            print("Channel message acknowledged!")
        except ConnectionError as e:
            print(f"Channel send failed: {e}")

        print("Waiting up to 10 s for a channel message...")
        msg = await ch.recv(timeout=10.0)
        if msg:
            print(f"[channel] {msg['sender']}: {msg['text']}")
        else:
            print("No channel message received.")

        # --- Direct / P2P ---
        # Use a node ID like "!d45b9db8" or a display name like "postar"
        peer = mesh.peer("!d45b9db8")

        print("Sending direct message (with ack/retry)...")
        try:
            await peer.send_text("Hello world!")
            print("Direct message acknowledged!")
        except ConnectionError as e:
            print(f"Direct send failed: {e}")

        print("Waiting up to 30 s for a direct reply...")
        dm = await peer.recv(timeout=30.0)
        if dm:
            print(f"[DM] {dm['sender']}: {dm['text']}")
        else:
            print("No direct message received.")

    except Exception as e:
        print(f"Exception: {e}")
    finally:
        mesh.close()
        print("Disconnected.")


if __name__ == "__main__":
    asyncio.run(main())
