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
    # 使用 AES 加密器，密钥为 'This is a key123'，模式为 CFB（无需填充），IV为 'This is an IV456'
    obj = AES.new(b'This is a key123', AES.MODE_CFB, b'This is an IV456')
    # 将明文字符串编码为 UTF-8 字节后加密，并返回密文
    return obj.encrypt(msg.encode('utf-8'))


def decryptMessage(msg):
    # 创建与加密时相同的 AES 加密器，用相同的密钥和 IV
    obj = AES.new(b'This is a key123', AES.MODE_CFB, b'This is an IV456')
    # 解密后将字节数据解码为 UTF-8 字符串
    return obj.decrypt(msg).decode('utf-8')


def makeDigest(msg):
    # 用 'shared secret key' 作为密钥，基于 SHA3-256 算法生成 HMAC 摘要字符串
    return hmac.new(b'shared secret key', msg, hashlib.sha3_256).hexdigest()


def recvMessage(conn):
    try:
        # 先接收固定长度的加密消息头（含长度 + HMAC摘要）
        dataHeader = decryptMessage(conn.recv(HEADER_LENGTH))
        if not dataHeader:
            sys.exit()  # 如果收到空数据，认为连接中断

        # 从解密后的 header 中解析消息长度和接收的 HMAC 摘要
        length, hashed = dataHeader.strip().split(':')
        messageLength = int(length)

        # 读取加密的消息主体
        msg = conn.recv(messageLength)

        # 重新计算摘要，与接收到的摘要比对，确保消息未被篡改
        if makeDigest(msg) == hashed:
            return decryptMessage(msg)  # 校验通过则解密后返回
        else:
            print("Message integrity compromised!")  # 摘要不一致表示消息被篡改
    except ConnectionResetError:
        # 如果连接被重置，关闭连接
        conn.close()


def sendMessage(conn, msgToSend):
    # 加密消息主体
    encrypted = encryptMessage(msgToSend)

    # 生成消息头（含消息长度和HMAC摘要），再加密（确保不被猜测）
    header = encryptMessage((str(len(msgToSend)) + ':' + makeDigest(encrypted)).ljust(HEADER_LENGTH))

    # 将加密后的消息头 + 加密消息正文 一起发送出去
    conn.sendall(header + encrypted)


def discover_server(timeout=5):
    # 创建一个 UDP socket
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 启用广播权限（SO_BROADCAST）
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # 客户端监听所有地址的广播端口（必须与服务器发送端口一致）
    udp_sock.bind(('', broadcast_port))

    # 设置 socket 超时时间，防止阻塞太久
    udp_sock.settimeout(timeout)

    try:
        while True:
            # 等待接收广播数据
            data, addr = udp_sock.recvfrom(1024)
            message = data.decode()

            # 识别有效广播信息格式：CHAT_SERVER:IP:PORT
            if message.startswith("CHAT_SERVER"):
                _, ip, port = message.split(':')
                return ip, int(port)  # 成功解析出服务器地址和端口
    except socket.timeout:
        # 超时后提示找不到服务器
        print("Server discovery timed out.")
        return None, None


# --- GUI界面 ---

class connectPage:
    def __init__(self, master):
        self.master = master  # 保存主窗口对象

        # 创建主画布 Canvas 作为背景容器
        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        # 在画布上添加 Frame，用于放置实际的输入框与按钮
        self.frame = tk.Frame(self.master, bg='#0f0e0f')  # 背景黑色
        self.frame.place(relx=0.1, rely=0.1, relwidth=0.8, relheight=0.8)  # 居中占80%

        # ----------------------------
        # 用户名输入部分
        # ----------------------------

        # 标签：“Enter your alias”
        self.userLabel = tk.Label(
            self.frame, text="Enter your alias:",
            bg="#0f0e0f", fg="#fffdfb", font=('Calibri', 12)
        )
        self.userLabel.place(relx=0.1, rely=0.2, relwidth=0.8, relheight=0.08)

        # 用户名输入框 Entry
        self.usernameEntry = tk.Entry(self.frame, font=("Calibri", 12))
        self.usernameEntry.place(relx=0.1, rely=0.3, relwidth=0.8, relheight=0.08)

        # ----------------------------
        # 密码输入部分
        # ----------------------------

        # 标签：“Enter your password”
        self.passLabel = tk.Label(
            self.frame, text="Enter your password:",
            bg="#0f0e0f", fg="#fffdfb", font=('Calibri', 12)
        )
        self.passLabel.place(relx=0.1, rely=0.4, relwidth=0.8, relheight=0.08)

        # 密码输入框 Entry（使用 • 作为掩码）
        bullet = "\u2022"  # 使用黑点字符作为密码掩码
        self.passEntry = tk.Entry(self.frame, font=("Calibri", 12), show=bullet)
        self.passEntry.place(relx=0.1, rely=0.5, relwidth=0.8, relheight=0.08)

        # ----------------------------
        # 登录与注册按钮
        # ----------------------------

        # “Connect” 按钮：点击后执行登录操作
        self.button = tk.Button(
            self.frame, text="Connect", font=("Calibri", 14),
            command=lambda: self.onClick(
                self.master, self.usernameEntry.get(), self.passEntry.get()
            )
        )
        self.button.place(relx=0.2, rely=0.65, relwidth=0.25, relheight=0.08)

        # “Register” 按钮：跳转到注册界面
        self.button2 = tk.Button(
            self.frame, text="Register", font=("Calibri", 14),
            command=self.gotoAccountPage
        )
        self.button2.place(relx=0.55, rely=0.65, relwidth=0.25, relheight=0.08)

    # ----------------------------
    # 登录按钮逻辑处理函数
    # ----------------------------
    def onClick(self, m, username, password):
        if len(username) and len(password):
            # 用户名和密码非空，执行登录控制器
            controller(m, username, password)
            # 登录完成后销毁当前界面
            self.canvas.destroy()
        else:
            # 弹出错误提示：不能为空
            errbox.showerror('Error', 'Entries cannot be empty.')

    # ----------------------------
    # 注册按钮逻辑处理函数
    # ----------------------------
    def gotoAccountPage(self):
        # 自动发现局域网内服务器 IP 与端口
        server_ip, server_port = discover_server()
        if server_ip is None:
            errbox.showerror('Error', 'Could not find server, please check your LAN.')
            return

        # 成功发现后与服务器建立 TCP 连接
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))

        # 跳转到注册界面
        self.canvas.destroy()
        createAccount(self.master, client_socket)


class createAccount:
    def __init__(self, master, conn):
        self.master = master          # 主窗口对象
        self.conn = conn              # 与服务器建立的 TCP 连接

        # 创建主画布，作为背景容器
        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        # 创建黑色背景的主框架 Frame，用于放置组件
        self.frame = tk.Frame(self.master, bg='#0f0e0f')
        self.frame.place(relx=0.1, rely=0.1, relwidth=0.8, relheight=0.8)

        # ----------------------------
        # 用户名输入部分
        # ----------------------------

        # 标签：“Choose an alias”
        self.userLabel = tk.Label(
            self.frame, text="Choose an alias:",
            bg="#0f0e0f", fg="#fffdfb", font=('Calibri', 15)
        )
        self.userLabel.place(relx=0.1, rely=0.2, relwidth=0.8, relheight=0.08)

        # 用户名输入框 Entry
        self.usernameEntry = tk.Entry(self.frame, font=("Calibri", 12))
        self.usernameEntry.place(relx=0.1, rely=0.3, relwidth=0.8, relheight=0.08)

        # ----------------------------
        # 密码输入部分
        # ----------------------------

        self.passLabel = tk.Label(
            self.frame, text="Choose a password:",
            bg="#0f0e0f", fg="#fffdfb", font=('Calibri', 15)
        )
        self.passLabel.place(relx=0.1, rely=0.4, relwidth=0.8, relheight=0.08)

        # 密码输入框（使用黑点“•”作为掩码）
        bullet = "\u2022"
        self.passEntry = tk.Entry(self.frame, font=("Calibri", 12), show=bullet)
        self.passEntry.place(relx=0.1, rely=0.5, relwidth=0.8, relheight=0.08)

        # ----------------------------
        # “Create Account” 按钮
        # ----------------------------
        self.button = tk.Button(
            self.frame, text="Create Account", font=("Calibri", 14),
            command=self.onClick  # 点击后执行注册逻辑
        )
        self.button.place(relx=0.2, rely=0.65, relwidth=0.25, relheight=0.08)

        # ----------------------------
        # “Back” 按钮（返回登录界面）
        # ----------------------------
        self.backButton = tk.Button(
            self.frame, text="Back", font=("Calibri", 14),
            command=self.backToLogin
        )
        self.backButton.place(relx=0.6, rely=0.65, relwidth=0.25, relheight=0.08)

    # 点击“Back”按钮后执行：销毁当前页面并返回登录界面
    def backToLogin(self):
        self.canvas.destroy()
        connectPage(self.master)

    # 点击“Create Account”按钮后执行：发送注册请求
    def onClick(self):
        username = self.usernameEntry.get()
        password = self.passEntry.get()

        if len(username) and len(password):
            # 构造 JSON 格式的数据，包含用户名、密码、create 标记
            data = {username: password, 'create': True}
            data = json.dumps(data)

            # 将注册数据发送给服务器
            sendMessage(self.conn, data)

            # 等待服务器返回注册结果
            serverResponse = recvMessage(self.conn)

            # 根据服务器返回的响应做出处理
            if serverResponse == "success":
                # 注册成功：弹出提示并返回登录界面
                errbox.showinfo('Info', 'Account created successfully!')
                self.canvas.destroy()
                connectPage(self.master)

            elif serverResponse == "dupuser":
                # 用户名已存在：弹出错误提示并清空输入框
                errbox.showerror('Error', 'User already exists.')
                self.usernameEntry.delete(0, tk.END)
                self.passEntry.delete(0, tk.END)
        else:
            # 有输入框为空：弹出错误提示
            errbox.showerror('Error', 'Entries cannot be empty.')


class chatPage:
    def __init__(self, master, que, conn, clientAlias):
        self.master = master              # 主窗口
        self.que = que                    # 用于异步接收消息的线程安全队列（Queue）
        self.conn = conn                  # 与服务器的 TCP 连接
        self.clientAlias = clientAlias    # 当前客户端的用户名

        # 创建主画布用于显示聊天窗口
        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        # 整个聊天界面的黑色背景框架
        self.frame = tk.Frame(self.master, bg='#242424')
        self.frame.place(relwidth=1, relheight=1)

        # ----------------------------
        # 消息显示区域（Text 组件）
        # ----------------------------
        self.text = tk.Text(
            self.frame,
            bg='#141414',         # 深灰色背景
            fg="#fffdfb",         # 默认字体颜色为白色
            font=("TkDefaultFont", 15),
            wrap=tk.WORD          # 自动换行按单词
        )

        # 配置三种文本颜色样式：发送者、接收者、系统提示
        self.text.tag_configure("sender", foreground="#04ffd9")   # 其他用户发来的消息（蓝绿）
        self.text.tag_configure("receiver", foreground="#ff8b16") # 自己发出的消息（橙色）
        self.text.tag_configure("info", foreground="#03ff07")     # 系统信息（绿色）

        # Text 区域位置
        self.text.place(relx=0.025, rely=0.025, relwidth=0.95, relheight=0.85)

        # 显示初始连接提示
        self.text.insert('end', f"Connected at {str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}\n", 'info')

        # ----------------------------
        # 用户输入框（Entry）
        # ----------------------------
        self.entry = tk.Entry(self.frame, font=("TkDefaultFont", 15))
        self.entry.place(relx=0.025, rely=0.9, relwidth=0.825, relheight=0.06)

        # 发送按钮：绑定点击发送消息函数
        self.button = tk.Button(
            self.frame, text="Send", font=("TkDefaultFont", 12),
            command=self.sendAndPrintMessage
        )
        self.button.place(relx=0.875, rely=0.9, relwidth=0.1, relheight=0.06)

    # 处理异步接收到的消息，展示在聊天框中
    def processIncoming(self):
        while not self.que.empty():
            data = self.que.get()
            sender = data.get("sender", "Unknown")
            msg = data.get("message", "")
            time_str = data.get("time", "[Unknown Time]")

            self.text.insert('end', f"\n{time_str} {sender}> ", 'sender')
            self.text.insert('end', msg)
            self.text.see('end')

    # 发送按钮的处理函数
    def sendAndPrintMessage(self):
        msgToSend = self.entry.get()
        if msgToSend:
            #  添加时间戳字段
            data = {
                "sender": self.clientAlias,
                "message": msgToSend,
                "time": datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
            }
            sendMessage(self.conn, json.dumps(data))
            self.entry.delete(0, tk.END)

            #  在本地窗口展示时使用同样时间
            self.text.insert('end', f"\n{data['time']} {self.clientAlias}> ", 'receiver')
            self.text.insert('end', msgToSend)
            self.text.see('end')


class controller:
    def __init__(self, master, username, password):
        self.master = master            # 主界面窗口对象
        self.username = username        # 用户输入的用户名
        self.password = password        # 用户输入的密码

        # -----------------------------
        # 自动发现服务器地址与端口
        # -----------------------------
        server_ip, server_port = discover_server()
        if server_ip is None:
            # 如果服务器未被发现，弹出提示框，返回登录界面
            errbox.showerror('Error', 'Could not find server.')
            return

        # -----------------------------
        # 与服务器建立 TCP 连接
        # -----------------------------
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((server_ip, server_port))

        # -----------------------------
        # 构造登录请求并发送
        # -----------------------------
        data = {
            self.username: self.password,  # 用户名 + 密码
            "create": False                # 表示是登录（而非注册）
        }
        data = json.dumps(data)            # 转换为 JSON 格式
        sendMessage(self.conn, data)       # 发送给服务器（加密 + 完整性校验）

        # -----------------------------
        # 等待服务器返回认证结果
        # -----------------------------
        serverResponse = recvMessage(self.conn)

        if serverResponse == "Y":
            # 登录成功，启动接收线程并打开聊天界面
            threadedRecv(self.master, self.conn, self.username)
        else:
            # 登录失败，弹出提示并关闭连接，回到登录界面
            errbox.showerror('Error', 'Login failed.')
            self.conn.close()
            connectPage(self.master)


class threadedRecv:
    def __init__(self, master, conn, clientAlias):
        self.master = master      # 主窗口（Tkinter 根窗口）
        self.que = Queue()        # 用于线程安全地传递收到的消息（Queue线程安全）
        self.conn = conn          # TCP连接 socket
        # 创建聊天界面 GUI，并传入消息队列用于异步展示
        self.gui = chatPage(master, self.que, conn, clientAlias)

        # 创建接收消息的后台线程（守护线程，程序退出时自动关闭）
        self.thread = Thread(target=self.recvAndQueueMessages, daemon=True)
        self.thread.start()       # 启动消息接收线程

        # 启动周期检查消息队列的函数，用于不断将接收的消息显示到聊天界面
        self.checkQueue()

    def checkQueue(self):
        # 调用 chatPage 中的 processIncoming() 将消息队列中的数据显示在窗口
        self.gui.processIncoming()

        # 每 200 毫秒重复检查一次消息队列
        self.master.after(200, self.checkQueue)

    def recvAndQueueMessages(self):
        while True:
            try:
                # 从 TCP 连接中接收消息（已加密、完整性校验）
                messageRcvd = recvMessage(self.conn)

                # 将 JSON 字符串反序列化为字典形式：{用户名: 消息内容}
                messageRcvd = json.loads(messageRcvd)

                # 将接收到的消息放入线程安全的队列中，供 UI 主线程显示
                self.que.put(messageRcvd)

                # 稍作延迟防止线程 CPU 占用过高
                time.sleep(0.2)

            except ConnectionResetError:
                # 如果服务器关闭连接，弹出提示框，结束接收线程
                errbox.showinfo('INFO', 'Server closed the connection.')
                return

def main():
    root = tk.Tk()
    root.title("Secure Chat Client")
    connectPage(root)
    root.mainloop()

if __name__ == '__main__':
    main()
