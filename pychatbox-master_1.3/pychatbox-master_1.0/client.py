import socket,random,string,sys,time,json,hashlib,hmac,ssl
from queue import Queue
import tkinter as tk
from tkinter.font import Font
import tkinter.messagebox as errbox
from threading import Thread
from Crypto.Cipher import AES
from datetime import datetime


HEIGHT = 900
WIDTH = 900

server_sni_hostname = 'example.com'
server_cert = '.\\certs\\server.crt'
client_cert = '.\\certs\\client.crt'
client_key = '.\\certs\\client.key'

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
context.load_cert_chain(certfile=client_cert, keyfile=client_key)

host = "192.168.0.108"
port = 5555

HEADER_LENGTH = 90

def key(length):
	letters = string.ascii_letters + string.digits
	return (''.join((random.choice(letters)) for i in range(length))).encode("utf-8")

def encrpytMessage(msg):
	obj = AES.new(b'This is a key123',AES.MODE_CFB,b'This is an IV456')
	encryptedMsg = obj.encrypt(msg.encode("utf-8"))
	return encryptedMsg

def decryptMessage(message):
	obj = AES.new(b'This is a key123',AES.MODE_CFB,b'This is an IV456')
	return obj.decrypt(message).decode("utf-8")

def makeDigest(msg):
    return hmac.new(b'shared secret key', msg, hashlib.sha3_256).hexdigest()

def recvMessage(conn):
    try:
        dataHeader = decryptMessage(conn.recv(HEADER_LENGTH))
        if not dataHeader:
            print("Connection closed by the client")
            sys.exit()
        length, hashed = dataHeader.strip().split(':')
        messageLength = int(length)
        msg = conn.recv(messageLength)
        msgDigest = makeDigest(msg)
        print(msgDigest)
        if msgDigest == hashed:
            return decryptMessage(msg)
        else:
            print("Someone is effing up with our security!")
    except ConnectionResetError:
        conn.close()

def sendMessage(conn,msgToSend):
    try:
        encryptedShit = encrpytMessage(msgToSend)
        msgToSend = encrpytMessage((str(len(msgToSend)) + ':' + makeDigest(encryptedShit)).ljust(HEADER_LENGTH)) + encryptedShit
        conn.sendall(msgToSend)
    except socket.error as e:
        print(e)
        

client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client_socket = context.wrap_socket(client_socket, server_side=False, server_hostname=server_sni_hostname)

def main():
        root = tk.Tk()
        root.title("Client Chat")
        connectPage(root)
        root.mainloop()

class createAccount:
    def __init__(self,master,conn):
        self.master = master
        self.conn = conn

        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        self.bg_img = tk.PhotoImage(file='.\\images\\newbg.png')
        self.bglabel = tk.Label(self.master, image=self.bg_img)
        self.bglabel.place(relwidth=1,relheight=1)

        self.frame = tk.Frame(self.master,bg='#0f0e0f')
        self.frame.place(relx=0.1,rely=0.1,relwidth=0.8, relheight=0.8)

        self.hostLabel = tk.Label(self.frame, height=150, width=150,text="Enter the server IP: ",bg="#0f0e0f",fg="#fffdfb",font=('Calibri',15))
        self.hostLabel.place(relx=0.025,rely=0.150,relwidth=0.500,relheight=0.060)

        self.hostEntry = tk.Entry(self.frame,font=("Calibri",10))
        self.hostEntry.place(relx=0.505,rely=0.150,relwidth=0.300,relheight=0.060)

        self.userLabel = tk.Label(self.frame,height=150, width=150,text="Enter an alias: ",bg="#0f0e0f",fg="#fffdfb",font=('Calibri',15))
        self.userLabel.place(relx=0.025,rely=0.275,relwidth=0.500,relheight=0.060)

        self.usernameEntry = tk.Entry(self.frame,font=("Calibri",10))
        self.usernameEntry.place(relx=0.505,rely=0.275,relwidth=0.300,relheight=0.060)

        self.passLabel = tk.Label(self.frame, height=150, width=150,text="Enter a Password: ",bg="#0f0e0f",fg="#fffdfb",font=('Calibri',15))
        self.passLabel.place(relx=0.025,rely=0.400,relwidth=0.500,relheight=0.060)

        bullet = "\u2022"
        self.passEntry = tk.Entry(self.frame,font=("Calibri",10),show=bullet)
        self.passEntry.place(relx=0.505,rely=0.400,relwidth=0.300,relheight=0.060)

        self.button = tk.Button(self.frame, text="Create Account", font=("Calibri",12),command=lambda : self.onClick(self.master,self.usernameEntry.get(),self.passEntry.get(),self.hostEntry.get()))
        self.button.place(relx=0.375,rely=0.500,relwidth=0.250,relheight=0.060)

    def onClick(self,master,username,password,h):
        if len(username) and len(password) and len(h):
            try:
                try:
                    print("helo!")
                    print(f"{client_socket.getsockname()} try")
                    self.sendNewCredentials(username,password)
                except:
                    client_socket.connect((h,port))
                    print(f"{client_socket.getsockname()} except")
                    self.sendNewCredentials(username,password)
            except socket.error as e:
                print(e)
                errbox.showerror('Error','Server is not active. Recheck the IP Address')
        else:
            errbox.showerror('error','Entered fields should not be empty')
    
    def sendNewCredentials(self,username,password):
        data = {username : password , 'create':True}
        data = json.dumps(data)
        sendMessage(self.conn, data)
        serverResponse = recvMessage(self.conn)
        if serverResponse == "success":
            errbox.showinfo('info','Account creation succeeded')
            self.canvas.destroy()
            connectPage(self.master)
        if serverResponse == "dupuser":
            errbox.showerror('error','User already exists. Please try again!')
            self.clearEntry(self.usernameEntry)
            self.clearEntry(self.passEntry)
            self.clearEntry(self.hostEntry)

    def clearEntry(self,entry):
        entry.delete(0,tk.END)


class connectPage:
    def __init__(self,master):
        self.master = master

        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        self.bg_img = tk.PhotoImage(file='.\\images\\newbg.png')
        self.bglabel = tk.Label(self.master, image=self.bg_img)
        self.bglabel.place(relwidth=1,relheight=1)

        self.frame = tk.Frame(self.master,bg='#0f0e0f')
        self.frame.place(relx=0.1,rely=0.1,relwidth=0.8, relheight=0.8)

        self.hostLabel = tk.Label(self.frame, height=150, width=150,text="Enter the IP to connect to: ",bg="#0f0e0f",fg="#fffdfb",font=('Calibri',12))
        self.hostLabel.place(relx=0.025,rely=0.150,relwidth=0.500,relheight=0.060)

        self.hostEntry = tk.Entry(self.frame,font=("Calibri",10))
        self.hostEntry.place(relx=0.505,rely=0.150,relwidth=0.300,relheight=0.060)

        self.userLabel = tk.Label(self.frame,height=150, width=150,text="Enter your alias: ",bg="#0f0e0f",fg="#fffdfb",font=('Calibri',12))
        self.userLabel.place(relx=0.025,rely=0.275,relwidth=0.500,relheight=0.060)

        self.usernameEntry = tk.Entry(self.frame,font=("Calibri",10))
        self.usernameEntry.place(relx=0.505,rely=0.275,relwidth=0.300,relheight=0.060)

        self.passLabel = tk.Label(self.frame,height=150, width=150,text="Enter your password: ",bg="#0f0e0f",fg="#fffdfb",font=('Calibri',12))
        self.passLabel.place(relx=0.025,rely=0.400,relwidth=0.500,relheight=0.060)

        bullet = "\u2022"
        self.passEntry = tk.Entry(self.frame,font=("Calibri",10),show=bullet)
        self.passEntry.place(relx=0.505,rely=0.400,relwidth=0.300,relheight=0.060)

        self.button = tk.Button(self.frame, text="Connect", font=("Calibri",12),command=lambda : self.onClick(self.master,self.hostEntry.get(),self.usernameEntry.get(),self.passEntry.get()))
        self.button.place(relx=0.300,rely=0.525,relwidth=0.150,relheight=0.060)

        self.button = tk.Button(self.frame, text="Register", font=("Calibri",12),command=lambda : self.gotoAccountPage())
        self.button.place(relx=0.500,rely=0.525,relwidth=0.175,relheight=0.060)

    def onClick(self,m,h,a,password):
        print(f"{m} {h} {a} {password}")
        if len(h) and len(a) and len(password):
            controller(m,h,a,password)
            self.canvas.destroy()
        else:
            errbox.showerror('error','The entries are not valid. Make sure no entry is blank.')
    
    def gotoAccountPage(self):
        self.canvas.destroy()
        createAccount(self.master, client_socket)
        

class chatPage:
    def __init__(self,master,que,conn,clientAlias):
        self.master = master
        self.frame = tk.Frame(master)
        self.frame.pack()
        self.que = que
        self.conn = conn
        self.clientAlias = clientAlias

        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        self.frame = tk.Frame(self.master,bg='#242424')
        self.frame.place(relwidth=1, relheight=1)

        self.text = tk.Text(self.frame,bg='#141414',fg="#fffdfb",font=("TkDefaultFont",15),wrap=tk.WORD)
        self.text.tag_configure("sender", foreground="#04ffd9")
        self.text.tag_configure("receiver", foreground="#ff8b16")
        self.text.tag_configure("info",foreground="#03ff07")
        self.text.tag_configure("right", justify="right")
        self.text.tag_configure("left", justify="left")
        self.text.place(relx = 0.025,rely=0.025,relwidth=0.950,relheight=0.850)
        self.text.insert('end',f"Connected to the Server at {str(datetime.now())}\n",'info')

        self.entry = tk.Entry(self.frame,font=("TkDefaultFont",15))
        self.entry.place(relx=0.025,rely=0.9,relwidth=0.825,relheight=0.060)

        self.button = tk.Button(self.frame, text="send", font=("TkDefaultFont",12),command=lambda : self.sendAndPrintMessage(self.entry.get()))
        self.button.place(relx=0.875,rely=0.9,relwidth=0.1,relheight=0.060)


    def processIncoming(self):
        while not self.que.empty():
            data = self.que.get()
            (clientAlias, msg), = data.items()
            self.text.insert('end',f"\n {clientAlias}> ",'sender')
            self.text.insert('end',msg,'left')
            self.text.see('end')

    def sendAndPrintMessage(self,msgToSend):
        if not msgToSend:
            pass
        else:
            data = {self.clientAlias : msgToSend}
            dataToSend = json.dumps(data)
            sendMessage(self.conn,dataToSend)
            self.clearEntry()
            self.text.insert('end',f"\n {self.clientAlias}> ",'receiver')
            self.text.insert('end',msgToSend)
            self.text.see('end')
            time.sleep(0.2)

    def clearEntry(self):
        self.entry.delete(0,tk.END)

class controller:
    def __init__(self,master,h,clientAlias,password):
        self.master = master
        self.h = h
        self.clientAlias = clientAlias
        self.password = password
        print("Looking for connection...")
        global client_socket
        try:
            try:
                print("helo!")
                print(self.h)
                print(client_socket)
                print(f"{client_socket.getsockname()} try")
                self.startOnValidation()
            except:
                client_socket.settimeout(0.5)
                client_socket.connect((self.h,port))
                client_socket.settimeout(None)
                print(f"{client_socket.getsockname()} except")
                self.startOnValidation()
        except socket.error as e:
            print(f"error : {e}")
            errbox.showerror('Error','Server is not active. Recheck the IP Address')
            client_socket.close()
            client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            client_socket = context.wrap_socket(client_socket, server_side=False, server_hostname=server_sni_hostname)
            connectPage(self.master)
            return

    def setClientAlias(self,alias):
        global client_socket
        data = {self.clientAlias : self.password, "create":False}
        data = json.dumps(data)
        sendMessage(client_socket,data)
        print("recving msg")
        serverResponse = recvMessage(client_socket)
        if serverResponse == "Y":
            return True
        else:
            errbox.showerror('Error',"Provided credentials are not valid")
            connectPage(self.master)

    def startOnValidation(self):
        if self.setClientAlias(self.clientAlias):
            print("Client alias set successfully!")
            threadedRecv(self.master,client_socket,self.clientAlias)

class threadedRecv:
    def __init__(self,master,conn,clientAlias):
        self.master = master
        self.que = Queue()
        self.conn = conn
        self.gui = chatPage(master,self.que,self.conn,clientAlias)
        self.thread = Thread(target=self.recvAndQueueMessages,daemon=True)
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
                errbox.showinfo('INFO','Server has closed the connection')
                return            
                
                
if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		sys.exit()



