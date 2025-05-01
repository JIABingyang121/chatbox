import socket, random, string, sys, time, json, hashlib, hmac, sqlite3
import tkinter as tk
import tkinter.messagebox as errbox
from queue import Queue
from threading import Thread
from Crypto.Cipher import AES
from datetime import datetime

HEIGHT = 900
WIDTH = 900

host = ''
port = 5555
broadcast_port = 37020
HEADER_LENGTH = 90
# 保存所有当前在线的客户端连接：{conn_socket: username}
activeConnections = {}
messageQueue = Queue()

def init_db():
    # 初始化本地 SQLite 数据库，用于存储用户账号密码哈希信息
    conn = sqlite3.connect('auth.db')         # 创建或连接数据库文件
    cursor = conn.cursor()

    # 创建认证表 authinfo（如不存在则自动创建）
    # 用户名为主键
    # 加盐哈希后的密码
    # 使用的盐值
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS authinfo (
            alias TEXT PRIMARY KEY,           
            passhash TEXT NOT NULL,           
            salt TEXT NOT NULL                
        )
    ''')
    conn.commit()     # 提交事务
    conn.close()      # 关闭数据库连接

def salt(length):
    # 生成随机盐值：由字母 + 数字组成的随机字符串
    letters = string.ascii_letters + string.digits
    return (''.join(random.choice(letters) for _ in range(length))).encode("utf-8")


def makeDigest(msg):
    # 使用固定密钥和 SHA3-256 哈希算法生成 HMAC（用于完整性校验）
    return hmac.new(b'shared secret key', msg, hashlib.sha3_256).hexdigest()

def passDigest(password):
    # 生成密码的哈希摘要以及使用的盐（用于注册）
    passalt = salt(16)  # 生成16字节随机盐
    hashed = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), passalt, 100000
    ).hex()
    return hashed, passalt.decode("utf-8")  # 返回十六进制哈希字符串和盐的明文

def calculateHash(password, passalt):
    # 根据给定密码和盐计算 PBKDF2-HMAC-SHA256 哈希（用于登录时验证）
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), passalt.encode("utf-8"), 100000).hex()

def encryptMessage(msg):
    # 使用 AES-CFB 模式加密字符串（同客户端保持一致的密钥与 IV）
    obj = AES.new(b'This is a key123', AES.MODE_CFB, b'This is an IV456')
    return obj.encrypt(msg.encode('utf-8'))

def decryptMessage(msg):
    obj = AES.new(b'This is a key123', AES.MODE_CFB, b'This is an IV456')
    return obj.decrypt(msg).decode('utf-8')

def recvMessage(conn):
    try:
        # 接收并解密消息头（包含消息长度 + 消息摘要）
        dataHeader = decryptMessage(conn.recv(HEADER_LENGTH))
        if not dataHeader:
            print("Connection closed by the client")
            sys.exit()

        # 从消息头中提取消息长度和摘要
        length, hashed = dataHeader.strip().split(':')
        messageLength = int(length)

        # 接收实际加密消息内容
        actualMsg = conn.recv(messageLength)

        # 重新计算消息摘要并校验完整性
        actualDigest = makeDigest(actualMsg)
        if actualDigest == hashed:
            return decryptMessage(actualMsg)  # 校验通过，解密返回
        else:
            print("Message integrity compromised!")  # HMAC不匹配，警告篡改
    except ConnectionResetError:
        print("Client disconnected!")  # 客户端异常断开连接


def sendMessage(conn, msgToSend):
    try:
        # 加密消息正文
        encryptedStuff = encryptMessage(msgToSend)

        # 构造加密的消息头：包含原文长度 + 摘要（HMAC）
        msgToSend = encryptMessage(
            (str(len(msgToSend)) + ':' + makeDigest(encryptedStuff)).ljust(HEADER_LENGTH)
        ) + encryptedStuff

        # 一次性发送消息头 + 加密内容
        conn.sendall(msgToSend)
    except socket.error as e:
        print(f"Error sending message: {e}")  # 发送失败时打印错误信息


def udp_broadcast():
    # 创建一个 UDP socket，用于发送广播
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 设置 socket 为广播模式
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # 获取本机 IP 地址（用于发送广播时填入）
    ip = socket.gethostbyname(socket.gethostname())

    # 构造广播内容格式：CHAT_SERVER:<ip>:<port>
    message = f"CHAT_SERVER:{ip}:{port}".encode('utf-8')

    while True:
        # 将服务器信息广播给整个局域网（端口由客户端监听）
        udp_sock.sendto(message, ('<broadcast>', broadcast_port))
        time.sleep(2)  # 每 2 秒广播一次，避免过于频繁


def createSocket():
    global server_socket
    # 创建一个 TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 将 socket 绑定到指定 IP 和端口
    server_socket.bind((host, port))
    # 设置监听模式，等待客户端连接
    server_socket.listen()

def acceptClients():
    # 清空当前活跃连接记录（防止重启时残留）
    activeConnections.clear()
    while True:
        # 接受一个客户端连接，请求到来时此处会阻塞
        conn, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        # 为每个客户端启动一个线程，处理其认证与通信逻辑
        Thread(target=clientThread, args=(conn, messageQueue)).start()

def main():
    try:
        init_db()  # 初始化认证数据库（如果没有则创建）
        createSocket()  # 创建并绑定 TCP socket（监听客户端连接）
        # 启动 UDP 广播线程，周期性向局域网广播自己的 IP/端口
        Thread(target=udp_broadcast, daemon=True).start()
        # 启动客户端接收线程，不断接受新的连接
        Thread(target=acceptClients, daemon=True).start()
        # 创建 GUI 窗口，显示服务器收到的消息
        root = tk.Tk()
        root.title("Server")
        updateGUI(root, "Server", messageQueue)  # 启动聊天界面监听消息队列
        root.mainloop()  # 启动事件循环，保持界面运行

    except KeyboardInterrupt:
        # 如果按下 Ctrl+C 或程序异常中断，关闭 socket 并退出
        server_socket.close()
        sys.exit()

class createGUI:
    def __init__(self, master, que, serverAlias):
        self.master = master              # 主窗口（Tkinter 根窗口）
        self.que = que                    # 用于接收消息的线程安全队列（由 clientThread 写入）
        self.serverAlias = serverAlias    # 服务器在聊天中显示的名称

        # 创建主画布
        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        # 创建主聊天框架（黑色背景）
        self.frame = tk.Frame(self.master, bg='#242424')
        self.frame.place(relwidth=1, relheight=1)

        # ----------------------------
        # 聊天信息展示区（Text 组件）
        # ----------------------------
        self.text = tk.Text(
            self.frame,
            bg='#141414',             # 深色背景
            fg="#fffdfb",             # 白色默认字体
            font=("TkDefaultFont", 15),
            wrap=tk.WORD              # 自动换行（按单词）
        )

        # 设置消息文本颜色样式
        self.text.tag_configure("sender", foreground="#04ffd9")   # 来自客户端的消息（青蓝）
        self.text.tag_configure("receiver", foreground="#ff8b16") # 来自服务器的消息（橙色）
        self.text.tag_configure("info", foreground="#03ff07")     # 系统信息（绿色）
        self.text.tag_configure("right", justify="right")         # 右对齐样式
        self.text.tag_configure("left", justify="left")           # 左对齐样式

        # 放置 Text 区域
        self.text.place(relx=0.025, rely=0.025, relwidth=0.950, relheight=0.850)

        # 显示初始欢迎消息
        self.text.insert("end", "Welcome to the chat application!", "info")

        # ----------------------------
        # 消息输入框（Entry）
        # ----------------------------
        self.entry = tk.Entry(self.frame, font=("TkDefaultFont", 15))
        self.entry.place(relx=0.025, rely=0.9, relwidth=0.825, relheight=0.060)

        # 发送按钮，点击后调用 sendAndPrintMessage 发送消息
        self.button = tk.Button(
            self.frame,
            text="send",
            font=("TkDefaultFont", 12),
            command=lambda: self.sendAndPrintMessage(self.entry.get())
        )
        self.button.place(relx=0.875, rely=0.9, relwidth=0.1, relheight=0.060)

    def processIncoming(self):
        while not self.que.empty():
            data = self.que.get()
            if isinstance(data, dict):
                sender = data.get("sender", "Unknown")
                msg = data.get("message", "")
                time_str = data.get("time", "[Unknown Time]")
                self.text.insert('end', f"\n{time_str} {sender}> ", 'sender')
                self.text.insert('end', msg)
                self.text.see('end')
            else:
                self.text.insert('end', f"\n\n{data}\n", 'info')

    def sendAndPrintMessage(self, msgToSend):
        if not msgToSend:
            return

        #  统一构造带时间的消息结构
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        data = {
            "sender": self.serverAlias,
            "message": msgToSend,
            "time": timestamp
        }
        dataString = json.dumps(data)

        #  广播给所有客户端
        for conn in activeConnections:
            sendMessage(conn, dataString)

        #  显示在自己窗口中
        self.clearEntry()
        self.text.insert('end', f"\n{timestamp} {self.serverAlias}> ", 'receiver')
        self.text.insert('end', msgToSend)
        self.text.see('end')

        time.sleep(0.2)

    def clearEntry(self):
        self.entry.delete(0,tk.END)
            

class updateGUI:
    def __init__(self, master, serverAlias, que):
        self.master = master               # 主窗口对象（Tkinter）
        self.serverAlias = serverAlias     # 服务器别名（用于界面显示）
        self.que = que                     # 消息队列，由 clientThread 负责向其中放入新消息

        # 创建主界面组件（createGUI），并传入消息队列用于展示消息
        self.gui = createGUI(master, self.que, self.serverAlias)

        # 启动消息队列检查机制（200ms自动刷新）
        self.checkQueue()

    def checkQueue(self):
        # 调用 createGUI 中的 processIncoming 方法
        # 将队列中的所有消息取出并显示到聊天窗口
        self.gui.processIncoming()

        # 使用 Tkinter 的 after 方法每 200ms 调用一次自己，实现非阻塞循环刷新
        self.master.after(200, self.checkQueue)
        

class clientThread:
    def __init__(self, conn, que):
        # 每当有新的客户端连接时就会实例化该类
        self.conn = conn          # 当前客户端的 TCP socket
        self.que = que            # 服务器界面显示用的线程安全消息队列
        self.createChatService(self.conn, self.que)  # 启动认证与聊天服务

    def getClientAlias(self, conn):
        # 连接到 SQLite 数据库，准备查询或插入用户信息
        connectionString = sqlite3.connect('auth.db')
        curs = connectionString.cursor()

        while True:
            try:
                # 接收客户端发来的 JSON 数据（包含用户名、密码、是否为注册请求）
                data = recvMessage(conn)
                data = json.loads(data)
                print(data)

                # 拆解键名：用户名 和 create 标志（注册 or 登录）
                clientAlias, createAccount = data.keys()

                if not data[createAccount]:  #登录请求
                    if self.checkValidClient(clientAlias, data[clientAlias], conn, connectionString, curs):
                        # 登录成功，将用户加入活跃连接
                        activeConnections[conn] = clientAlias
                        print(activeConnections)
                        return

                else:  #注册请求
                    # 查询该用户名是否已存在
                    query = f"SELECT alias FROM authinfo WHERE alias LIKE '{clientAlias}'"
                    curs.execute(query)
                    result = curs.fetchone()

                    if not result:
                        # 用户名可用，进行注册
                        digest, passSalt = passDigest(data[clientAlias])
                        query = f"INSERT INTO authinfo (alias, passhash, salt) VALUES ('{clientAlias}', '{digest}', '{passSalt}')"
                        curs.execute(query)
                        connectionString.commit()
                        sendMessage(conn, "success")
                    else:
                        # 用户名已存在
                        sendMessage(conn, "dupuser")

            except socket.timeout as e:
                # 如果超时，关闭服务器 socket 并退出（用于调试或容错）
                print(f"Encountered an error! {e} No worries")
                server_socket.close()
                sys.exit()

    def checkValidClient(self, clientAlias, password, conn, connstr, cs):
        try:
            # 查找该用户在数据库中的记录（哈希 + 盐）
            query = f"SELECT alias, passhash, salt FROM authinfo WHERE alias LIKE '{clientAlias}'"
            cs.execute(query)
            result = cs.fetchone()
            alias, passhash, passalt = result

            if result:
                print(alias)
                # 计算客户端输入的密码哈希值
                givenPassHash = calculateHash(password, passalt)

                if passhash == givenPassHash:
                    print("User is in the list")
                    sendMessage(conn, "Y")  # 认证成功
                    return True
                else:
                    print("User not in our list")
                    sendMessage(conn, "N")  # 认证失败
                    return False
        except:
            print("Here! User not in our list")
            sendMessage(conn, "N")
            return False

    def verifyUsername(self, conn):
        # 创建线程执行 getClientAlias（防止阻塞主线程）
        authThread = Thread(target=self.getClientAlias, args=(conn,))
        authThread.start()
        authThread.join()  # 等待认证完成后再继续
        # 向消息队列推送系统提示消息（登录成功）
        self.que.put(f"Connected to {activeConnections[conn]} at {str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}")

    def recvFromClient(self, conn):
        while True:
            try:
                raw_msg = recvMessage(self.conn)
                parsed_msg = json.loads(raw_msg)

                # 1. 广播该 JSON 消息（含 sender、message、time）
                for connection in activeConnections.copy():
                    if connection is not self.conn:
                        sendMessage(connection, json.dumps(parsed_msg))

                # 2. 同步推送给 GUI 展示
                self.que.put(parsed_msg)
                time.sleep(0.2)  # 延迟防止线程过载
            except socket.error:
                # 客户端关闭连接或异常断开
                errbox.showinfo('INFO', f'Client {activeConnections[conn]} has closed the connection')
                return

    def createChatService(self, conn, que):
        self.verifyUsername(conn)  # 登录/注册认证
        recvThread = Thread(target=self.recvFromClient, args=(conn,))  # 创建接收线程
        recvThread.start()
        recvThread.join()  # 等待线程结束（连接关闭）

        # 客户端断开后，从活跃连接中移除
        del activeConnections[conn]
        conn.close()  # 关闭该客户端连接


if __name__ == "__main__":
    main()


    
