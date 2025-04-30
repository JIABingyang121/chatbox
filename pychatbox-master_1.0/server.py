import socket,random,string,sys,time,json,hashlib,hmac,sqlite3,ssl
import tkinter as tk
import tkinter.messagebox as errbox
from queue import Queue
from threading import Thread
from Crypto.Cipher import AES
from datetime import datetime

HEIGHT = 900
WIDTH = 900

host = ""
port = 5555
HEADER_LENGTH = 90

server_cert = '.\\certs\\server.crt'
server_key = '.\\certs\\server.key'

client_certs = '.\\certs\\client.crt'

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(certfile=server_cert, keyfile=server_key)
context.load_verify_locations(cafile=client_certs)

activeConnections = {}
messageQueue = Queue()
def init_db():
    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS authinfo (
            alias TEXT PRIMARY KEY,
            passhash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def salt(length):
    letters = string.ascii_letters + string.digits
    return (''.join((random.choice(letters)) for i in range(length))).encode("utf-8")

def makeDigest(msg):
    return hmac.new(b'shared secret key', msg , hashlib.sha3_256).hexdigest()

def passDigest(password):
    passalt = salt(16)
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), passalt, 100000).hex(), passalt.decode("utf-8")

def calculateHash(password,passalt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), passalt.encode("utf-8"), 100000).hex()

def encryptMessage(msg):
    obj = AES.new(b'This is a key123',AES.MODE_CFB,b'This is an IV456')
    encryptedMsg = obj.encrypt(msg.encode("utf-8"))
    return encryptedMsg

def decryptMessage(msg):
    obj = AES.new(b'This is a key123',AES.MODE_CFB,b'This is an IV456')
    return obj.decrypt(msg).decode("utf-8")

def recvMessage(conn):
    try:
        dataHeader = conn.recv(HEADER_LENGTH)
        dataHeader = decryptMessage(dataHeader)
        if not dataHeader:
            print("Connection closed by the client")
            sys.exit()
        length, hashed = dataHeader.strip().split(':')
        messageLength = int(length)
        actualMsg = conn.recv(messageLength)
        actualDigest = makeDigest(actualMsg)
        if actualDigest == hashed:
            return decryptMessage(actualMsg)
        else:
            print("Someone is effing up with our security!")
    except ConnectionResetError:
        print("Client disconnected!")

def sendMessage(conn,msgToSend):
    try:
        encyrptedStuff = encryptMessage(msgToSend)
        msgToSend = encryptMessage((str(len(msgToSend)) + ':' + makeDigest(encyrptedStuff)).ljust(HEADER_LENGTH)) + encyrptedStuff
        conn.sendall(msgToSend)
    except socket.error as e:
        print(f"Encountered an error while sending msg to {activeConnections[conn]}\n {e}")

def createSocket():
    try:
        global server_socket
        server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server_socket.bind((host,port))
        server_socket.listen()
        print("Listening...")
    except socket.error as e:
         print(f'{e}\nThe socket object could not be created.')

def acceptClients():
    activeConnections.clear()
    while True:
        try:
            conn = (server_socket.accept())[0]
            conn = context.wrap_socket(conn, server_side=True)
            newthread = Thread(target=clientThread,args=(conn,messageQueue,))
            print('I made a new thread!')
            newthread.start()
        except socket.error as e:
            print(f"Encountered an error\n {e}")
        except:
            return
       
def main(): 
    try:
        createSocket()
        t = Thread(target=acceptClients)
        t.start()
        while not activeConnections:
            time.sleep(0.5)
        print(activeConnections)
        root = tk.Tk()
        root.title("Server")
        updateGUI(root,"Server",messageQueue)
        root.mainloop()
    except socket.error:
        server_socket.close()
        sys.exit()

class createGUI:
    def __init__(self,master,que,serverAlias):
        self.master = master
        self.frame = tk.Frame(master)
        self.frame.pack()
        self.que = que
        self.serverAlias = serverAlias

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
        self.text.insert("end","Welcome to the chat application!")

        self.entry = tk.Entry(self.frame,font=("TkDefaultFont",15))
        self.entry.place(relx=0.025,rely=0.9,relwidth=0.825,relheight=0.060)

        self.button = tk.Button(self.frame, text="send", font=("TkDefaultFont",12),command=lambda : self.sendAndPrintMessage(self.entry.get()))
        self.button.place(relx=0.875,rely=0.9,relwidth=0.1,relheight=0.060)
    

    def processIncoming(self):
        while not self.que.empty():
            data = self.que.get()
            if type(data) is dict:
                (clientAlias, msg), = data.items()
                self.text.insert('end',f"\n {clientAlias}> ",'sender')
                self.text.insert('end',msg)
                self.text.see('end')
            else:
                self.text.insert('end',f"\n\n{data}\n",'info')

    def sendAndPrintMessage(self,msgToSend):
        if not msgToSend:
            pass
        else:
            data = {'Server': msgToSend}
            dataString = json.dumps(data)
            for conn in activeConnections:
                sendMessage(conn,dataString)
            self.clearEntry()
            self.text.insert('end',f"\n {self.serverAlias}> ",'receiver')
            self.text.insert('end',msgToSend)
            self.text.see('end')
            time.sleep(0.2)

    def clearEntry(self):
        self.entry.delete(0,tk.END)
            

class updateGUI:
    def __init__(self,master,serverAlias,que):
        self.master = master
        self.serverAlias = serverAlias
        self.que = que
        self.gui = createGUI(master,self.que,self.serverAlias)
        self.checkQueue()
    
    def checkQueue(self):
        self.gui.processIncoming()
        self.master.after(200, self.checkQueue)
        

class clientThread:
    def __init__(self,conn,que):
        #will invoke this method when a connection is established while having blocked threads
        self.conn = conn
        self.que = que
        self.createChatService(self.conn,self.que)

    def getClientAlias(self,conn):
        connectionString = sqlite3.connect('auth.db')
        curs = connectionString.cursor()
        while True:
            try:
                data = recvMessage(conn)
                data = json.loads(data)
                print(data)
                clientAlias,createAccount = data.keys()
                if not data[createAccount]:
                    if self.checkValidClient(clientAlias,data[clientAlias],conn,connectionString,curs):
                        activeConnections[conn] = clientAlias
                        print(activeConnections)
                        return
                else:
                    query = f"SELECT alias FROM authinfo WHERE alias LIKE '{clientAlias}'"
                    curs.execute(query)
                    result = curs.fetchone()
                    if not result:
                        print(passDigest(data[clientAlias]))
                        digest, passSalt = passDigest(data[clientAlias])
                        query = f"INSERT INTO authinfo (alias,passhash,salt) VALUES ('{clientAlias}','{digest}','{passSalt}')"
                        curs.execute(query)
                        connectionString.commit()
                        sendMessage(conn,"success")
                    else:
                        sendMessage(conn,"dupuser")
            except socket.timeout as e:
                print(f"Encountered an error! {e} No worries")
                server_socket.close()
                sys.exit()

    def checkValidClient(self,clientAlias,password,conn,connstr,cs):
        try:
            query = f"SELECT alias,passhash,salt FROM authinfo WHERE alias LIKE '{clientAlias}'"
            cs.execute(query)
            result = cs.fetchone()
            alias, passhash, passalt = result
            if result:
                print(alias)
                givenPassHash = calculateHash(password,passalt)
                if passhash == givenPassHash:
                    print("User is in the list")
                    sendMessage(conn,"Y")
                    return True
                else:
                    print("User not in our list")
                    sendMessage(conn,"N")
                    return False
        except:
            print("Here! User not in our list")
            sendMessage(conn,"N")
            return False

    def verifyUsername(self,conn):
        authThread = Thread(target=self.getClientAlias,args=(conn,))
        authThread.start()
        authThread.join()
        self.que.put(f"Connected to {activeConnections[conn]} at {str(datetime.now())}")
    
    def recvFromClient(self,conn):
        while True:
            try:
                messageRcvd = recvMessage(self.conn)
                tempDict = activeConnections.copy()
                for connection in tempDict:
                    if connection is not conn:
                        sendMessage(connection, messageRcvd)
                messageRcvd = json.loads(messageRcvd)
                self.que.put(messageRcvd)
                time.sleep(0.2)
            except socket.error:
                errbox.showinfo('INFO',f'Client {activeConnections[conn]} has closed the connection')
                return        

    def createChatService(self,conn,que):
        self.verifyUsername(conn)
        recvThread = Thread(target=self.recvFromClient,args=(conn,))
        recvThread.start()
        recvThread.join()
        del activeConnections[conn]
        conn.close()
            
if __name__ == "__main__":
    init_db()
    main()


    
