"""
Create secret data.
"""

import base64
import subprocess
from tkinter import *
from tkinter import ttk


root = Tk()
root.title("I Done Know")


passphrase = StringVar(value="")
encrypted_text = StringVar(value="")


def decrypt():
    try:
        ascii = encrypted_text.get()
        bytes = base64.b64decode(ascii)
        with open("/tmp/update.gpg", 'wb') as f:
            f.write(bytes)
        p = subprocess.Popen("gpg --passphrase-fd 0 --no-tty -d /tmp/update.gpg", shell=True,
                             stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        stdin_bytes = ("%s\n" % passphrase.get()).encode("ascii")
        p.stdin.write(stdin_bytes)
        p.stdin.close()
        output = p.stdout.read()
        decrypted_text.delete(1.0, END)
        decrypted_text.insert(1.0, output)
        p.wait()
    except Exception as e:
        decrypted_text.delete(1.0, END)
        decrypted_text.insert(1.0, "Error: %s" % e)


def encrypt():
    try:
        words = decrypted_text.get(1.0, END)
        p = subprocess.Popen("gpg --passphrase-fd 0 --no-tty -c", shell=True,
                             stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        passphrase_bytes = ("%s\n" % passphrase.get()).encode("ascii")
        p.stdin.write(passphrase_bytes)
        p.stdin.write(words.encode("ascii"))
        p.stdin.close()

        output = p.stdout.read()
        p.wait()
        ascii_output = base64.b64encode(output)

        encrypted_text.set(ascii_output)
    except Exception as e:
        encrypted_text.set("Error: %s" % e)


content = ttk.Frame(root)
content.grid(column=0, row=0)

frame = ttk.Frame(content, borderwidth=5, relief="sunken")
frame.grid(column=0, row=0, columnspan=1, rowspan=1, sticky=(N, S, E, W))

pp_label = ttk.Label(frame, text='Passphrase')
pp_label.grid(column=0, row=0, columnspan=1, rowspan=1)
pp_entry = ttk.Entry(frame, textvariable=passphrase, show="*")
pp_entry.grid(column=1, row=0, columnspan=1, rowspan=1)

enc_label = ttk.Label(frame, text='Encrypted Text')
enc_label.grid(column=0, row=1, columnspan=2, rowspan=1)
enc_entry = ttk.Entry(frame, textvariable=encrypted_text)
enc_entry.grid(column=0, row=2, columnspan=2, rowspan=3, sticky=(N, S, E, W))


dec_label = ttk.Label(frame, text='Decrypted Text')
dec_label.grid(column=0, row=5, columnspan=2, rowspan=1)
decrypted_text = Text(frame)
decrypted_text.grid(column=0, row=6, columnspan=2, rowspan=4, sticky=(N, S, E, W))



enc_button = ttk.Button(frame, text="Encrypt", command=encrypt)
enc_button.grid(column=0, row=11, columnspan=1, rowspan=1)

dec_button = ttk.Button(frame, text="Decrypt", command=decrypt)
dec_button.grid(column=1, row=11, columnspan=1, rowspan=1)

root.mainloop()

