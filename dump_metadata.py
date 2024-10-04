import frida

device = frida.get_usb_device()
application = device.get_frontmost_application()
session = device.attach(application.pid)

cnt = 1
def my_message_handler(message, payload):
    global cnt
    if "payload" in message and message["payload"] == "metadata":
        print("Dumping metadata...")
        with open(f"global-metadata-{cnt}.dat", "wb") as f:
            f.write(payload)
        print("Done!")
        cnt += 1

with open('script.js', 'r', encoding='utf-8') as f:
    js = f.read()
script = session.create_script(js)
script.on("message", my_message_handler)
script.load()

input()
