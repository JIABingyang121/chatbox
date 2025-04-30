import socket, random, string, sys, time, json, hashlib, hmac
import tkinter as tk
import tkinter.messagebox as errbox
from threading import Thread
from queue import Queue
from Crypto.Cipher import AES
from datetime import datetime

HEIGHT = 900
WIDTH = 900

HEADER_LENGTH = 90
broadcast_port = 37020

def encryptMessage(msg):
    obj = AES.new(b'This is a key123', AES.MODE_CFB, b'This is an IV456')
    return obj.encrypt(msg.encode('utf-8'))

def decryptMessage(msg):
    obj = AES.new(b'This is a key123', AES.MODE_CFB, b'This is an IV456')
    return obj.decrypt(msg).decode('utf-8')

def makeDigest(msg):
    return hmac.new(b'shared secret key', msg, hashlib.sha3_256).hexdigest()

def recvMessage(conn):
    try:
        dataHeader = decryptMessage(conn.recv(HEADER_LENGTH))
        if not dataHeader:
            sys.exit()
        length, hashed = dataHeader.strip().split(':')
        messageLength = int(length)
        msg = conn.recv(messageLength)
        if makeDigest(msg) == hashed:
            return decryptMessage(msg)
        else:
            print("Message integrity compromised!")
    except ConnectionResetError:
        conn.close()

def sendMessage(conn, msgToSend):
    encrypted = encryptMessage(msgToSend)
    header = encryptMessage((str(len(msgToSend)) + ':' + makeDigest(encrypted)).ljust(HEADER_LENGTH))
    conn.sendall(header + encrypted)

def discover_server(timeout=5):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_sock.bind(('', broadcast_port))
    udp_sock.settimeout(timeout)
    try:
        while True:
            data, addr = udp_sock.recvfrom(1024)
            message = data.decode()
            if message.startswith("CHAT_SERVER"):
                _, ip, port = message.split(':')
                return ip, int(port)
    except socket.timeout:
        print("Server discovery timed out.")
        return None, None

# --- GUI界面 ---

class connectPage:
    def __init__(self, master):
        self.master = master

        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        self.frame = tk.Frame(self.master, bg='#0f0e0f')
        self.frame.place(relx=0.1, rely=0.1, relwidth=0.8, relheight=0.8)

        self.userLabel = tk.Label(self.frame, text="Enter your alias:", bg="#0f0e0f", fg="#fffdfb", font=('Calibri', 12))
        self.userLabel.place(relx=0.1, rely=0.2, relwidth=0.8, relheight=0.08)

        self.usernameEntry = tk.Entry(self.frame, font=("Calibri", 12))
        self.usernameEntry.place(relx=0.1, rely=0.3, relwidth=0.8, relheight=0.08)

        self.passLabel = tk.Label(self.frame, text="Enter your password:", bg="#0f0e0f", fg="#fffdfb", font=('Calibri', 12))
        self.passLabel.place(relx=0.1, rely=0.4, relwidth=0.8, relheight=0.08)

        bullet = "\u2022"
        self.passEntry = tk.Entry(self.frame, font=("Calibri", 12), show=bullet)
        self.passEntry.place(relx=0.1, rely=0.5, relwidth=0.8, relheight=0.08)

        self.button = tk.Button(self.frame, text="Connect", font=("Calibri", 14), command=lambda: self.onClick(self.master, self.usernameEntry.get(), self.passEntry.get()))
        self.button.place(relx=0.2, rely=0.65, relwidth=0.25, relheight=0.08)

        self.button2 = tk.Button(self.frame, text="Register", font=("Calibri", 14), command=lambda: self.gotoAccountPage())
        self.button2.place(relx=0.55, rely=0.65, relwidth=0.25, relheight=0.08)

        

    def onClick(self, m, username, password):
        if len(username) and len(password):
            controller(m, username, password)
            self.canvas.destroy()
        else:
            errbox.showerror('Error', 'Entries cannot be empty.')
    


    def gotoAccountPage(self):
        server_ip, server_port = discover_server()
        if server_ip is None:
            errbox.showerror('Error', 'Could not find server, please check your LAN.')
            return
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))
        self.canvas.destroy()
        createAccount(self.master, client_socket)

class createAccount:
    def __init__(self, master, conn):
        self.master = master
        self.conn = conn

        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        self.frame = tk.Frame(self.master, bg='#0f0e0f')
        self.frame.place(relx=0.1, rely=0.1, relwidth=0.8, relheight=0.8)

        self.userLabel = tk.Label(self.frame, text="Choose an alias:", bg="#0f0e0f", fg="#fffdfb", font=('Calibri', 15))
        self.userLabel.place(relx=0.1, rely=0.2, relwidth=0.8, relheight=0.08)

        self.usernameEntry = tk.Entry(self.frame, font=("Calibri", 12))
        self.usernameEntry.place(relx=0.1, rely=0.3, relwidth=0.8, relheight=0.08)

        self.passLabel = tk.Label(self.frame, text="Choose a password:", bg="#0f0e0f", fg="#fffdfb", font=('Calibri', 15))
        self.passLabel.place(relx=0.1, rely=0.4, relwidth=0.8, relheight=0.08)

        bullet = "\u2022"
        self.passEntry = tk.Entry(self.frame, font=("Calibri", 12), show=bullet)
        self.passEntry.place(relx=0.1, rely=0.5, relwidth=0.8, relheight=0.08)

        self.button = tk.Button(self.frame, text="Create Account", font=("Calibri", 14), command=self.onClick)
        self.button.place(relx=0.2, rely=0.65, relwidth=0.25, relheight=0.08)
        
        self.backButton = tk.Button(self.frame, text="Back", font=("Calibri", 14), command=self.backToLogin)
        self.backButton.place(relx=0.6, rely=0.65, relwidth=0.25, relheight=0.08)
    def backToLogin(self):
        self.canvas.destroy()
        connectPage(self.master)


    def onClick(self):
        username = self.usernameEntry.get()
        password = self.passEntry.get()
        if len(username) and len(password):
            data = {username: password, 'create': True}
            data = json.dumps(data)
            sendMessage(self.conn, data)
            serverResponse = recvMessage(self.conn)
            if serverResponse == "success":
                errbox.showinfo('Info', 'Account created successfully!')
                self.canvas.destroy()
                connectPage(self.master)
            elif serverResponse == "dupuser":
                errbox.showerror('Error', 'User already exists.')
                self.usernameEntry.delete(0, tk.END)
                self.passEntry.delete(0, tk.END)
        else:
            errbox.showerror('Error', 'Entries cannot be empty.')

class chatPage:
    def __init__(self, master, que, conn, clientAlias):
        self.master = master
        self.que = que
        self.conn = conn
        self.clientAlias = clientAlias

        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        self.frame = tk.Frame(self.master, bg='#242424')
        self.frame.place(relwidth=1, relheight=1)

        self.text = tk.Text(self.frame, bg='#141414', fg="#fffdfb", font=("TkDefaultFont", 15), wrap=tk.WORD)
        self.text.tag_configure("sender", foreground="#04ffd9")
        self.text.tag_configure("receiver", foreground="#ff8b16")
        self.text.tag_configure("info", foreground="#03ff07")
        self.text.place(relx=0.025, rely=0.025, relwidth=0.95, relheight=0.85)
        self.text.insert('end', f"Connected at {str(datetime.now())}\n", 'info')

        self.entry = tk.Entry(self.frame, font=("TkDefaultFont", 15))
        self.entry.place(relx=0.025, rely=0.9, relwidth=0.825, relheight=0.06)

        self.button = tk.Button(self.frame, text="Send", font=("TkDefaultFont", 12), command=self.sendAndPrintMessage)
        self.button.place(relx=0.875, rely=0.9, relwidth=0.1, relheight=0.06)

    def processIncoming(self):
        while not self.que.empty():
            data = self.que.get()
            (clientAlias, msg), = data.items()
            self.text.insert('end', f"\n{clientAlias}> ", 'sender')
            self.text.insert('end', msg)
            self.text.see('end')

    def sendAndPrintMessage(self):
        msgToSend = self.entry.get()
        if msgToSend:
            data = {self.clientAlias: msgToSend}
            dataToSend = json.dumps(data)
            sendMessage(self.conn, dataToSend)
            self.entry.delete(0, tk.END)
            self.text.insert('end', f"\n{self.clientAlias}> ", 'receiver')
            self.text.insert('end', msgToSend)
            self.text.see('end')

class controller:
    def __init__(self, master, username, password):
        self.master = master
        self.username = username
        self.password = password

        server_ip, server_port = discover_server()
        if server_ip is None:
            errbox.showerror('Error', 'Could not find server.')
            return

        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((server_ip, server_port))

        data = {self.username: self.password, "create": False}
        data = json.dumps(data)
        sendMessage(self.conn, data)

        serverResponse = recvMessage(self.conn)
        if serverResponse == "Y":
            threadedRecv(self.master, self.conn, self.username)
        else:
            errbox.showerror('Error', 'Login failed.')
            self.conn.close()
            connectPage(self.master)

class threadedRecv:
    def __init__(self, master, conn, clientAlias):
        self.master = master
        self.que = Queue()
        self.conn = conn
        self.gui = chatPage(master, self.que, conn, clientAlias)
        self.thread = Thread(target=self.recvAndQueueMessages, daemon=True)
        self.thread.start()
        self.checkQueue()

    def checkQueue(self):
        self.gui.processIncoming()
        self.master.after(200, self.checkQueue)

    def recvAndQueueMessages(self):
        while True:
            try:
                messageRcvd = recvMessage(self.conn)
                messageRcvd = json.loads(messageRcvd)
                self.que.put(messageRcvd)
                time.sleep(0.2)
            except ConnectionResetError:
                errbox.showinfo('INFO', 'Server closed the connection.')
                return

def main():
    root = tk.Tk()
    root.title("Secure Chat Client")
    connectPage(root)
    root.mainloop()

if __name__ == '__main__':
    main()
