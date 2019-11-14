import threading
import time
import itertools
import random
import socket
import re
import os


# 展示爆破结果并且让用户可以进行操作          还没做完，先构思再写吧
def result_show():
    print("爆破完成，结果为：")
    items = sorted(response_length.items(), key=lambda x: x[0])
    if len(keywords) != 0:
        for i in keywords:
            for response_info in response_information:
                if i in response_info[2]:
                    print("发现keyword!!!:")
                    print("**** keyword: ****")
                    print(i)
                    print("**** payload: ****")
                    print(i[5])
                    print("**** response: ****")
                    print(i[2])
    while 1:
        for i in items:
            print("长度为：" + str(i[0]) + "  的响应包有: =================>  " + str(i[1]) + "  个")
        length = int(input("输入你希望查看多大长度的数据包的详细信息:   "))
        for i in response_information:
            if i[1] == length:
                print("-------------------------------------")
                print("**** payload: ****")
                print(i[5])
                print("**** response: ****")
                print(i[2])
        if input("继续？(Y/n)") not in ("Y", "y", "yes", ""):
            break


# 数据分析
def analyse_response(response, request, cluster):
    global response_information
    flag = 0
    response_length = len(response)
    if len(response_information) == 0:
        id = 1
        length = response_length
        response_body = response
        num = 1
        response_information.append((id, length, response_body, num, request, cluster))
    else:
        for i in response_information:
            if i[1] == response:
                i[3] += 1
                flag = 1
                break
        if flag == 0:
            id = len(response_information)
            length = response_length
            response_body = response
            num = 1
            response_information.append((id, length, response_body, num, request, cluster))


# 参数菜单
def get_choice():
    global sleep_time, thread_num, if_random_user_agent, keywords
    choice = 999
    while choice != 0:
        print("以下有部分可选参数是否需要修改：")
        print("1. 线程数（默认线程数为20）")
        print("2. 每次发包停顿时长（默认无停顿）")
        print("3. 是否需要随机生成 User-Agent（默认不随机生成）")
        print("4. 是否检测response中的关键字")
        print("0. 无需修改，直接开始爆破")
        choice = int(input("输入你的选择："))
        if choice == 0:
            os.system('cls')
            print_logo()
            break
        elif choice == 1:
            thread_num = int(input("输入你想要设置的线程数（默认为20）"))
        elif choice == 2:
            sleep_time = int(input("输入你想要设置的停顿时间（单位为秒）"))
        elif choice == 3:
            if_random_user_agent = 1
            print("已开启随机生成User-Agent")
        elif choice == 4:
            keywords = input("请输入希望设置的关键字（多个关键字以空格分离）：\n").split()
        if input("是否继续设置参数：(Y/n)") not in ('y', 'Y', 'yes', ''):
            os.system('cls')
            print_logo()
            break
        os.system('cls')
        print_logo()


# 打印logo
def print_logo():
    print(r" ___ _ __   __ _ _ __| | __")
    print(r"/ __| '_ \ / _` | '__| |/ /")
    print(r"\__ \ |_) | (_| | |  |   <")
    print(r"|___/ .__/ \__,_|_|  |_|\_\ ")
    print(r"    |_|                    ")
    print("\n此工具由spark安全团队制作并开源:D")
    print("欢迎大家访问我们的官方网站： http://www.sparksec.online\n\n")


# 计算需要加载文件的密码值
def calc_pass_num(request):
    cluster_num = len(re.findall(r"\{cluster\[.+?\]\}", request))
    pitchfork_num = len(re.findall(r"\{pitchfork\[.+?\]\}", request))
    return cluster_num, pitchfork_num


# 随机User-Agent值
def random_user_agent(request):
    with open("dist/user-agents.txt", 'r') as f:
        user_agent_list = f.read().split('\n')
    return re.sub(r"User-Agent: .+", "User-Agent: " + random.choice(user_agent_list), request)


# 读取字典内容转换成数组
def get_pass(filenames):
    cluster = []
    for filename in filenames:
        with open(filename , 'r') as f:
            cluster.append(f.read().split())
    if len(filenames) == 1:
        clusters = cluster[0]
    else:
        clusters = list(itertools.product(*cluster))         # 计算笛卡尔积
    return clusters


# 得到pitchfork字段
def get_pitchfork(cluster, pitchfork):
    result = []
    for i in pitchfork :
        result.append(cluster[i])
    return result


# 计算content-lenght
def calc_lenght(request):
    content = re.findall("\n\n(.+)", request)[0]
    lenght = len(content)
    request = re.sub(r"Content-Length: [0-9]+", "Content-Length: " + str(lenght), request)
    return request


# 随机伪装 ip
def get_random_ip(request):
    ip = str(random.randint(0, 255)) + "." + str(random.randint(0, 255)) + "." + str(random.randint(0, 255)) + "." + str(random.randint(0, 255))
    # 伪造 x-forwarded-for
    if re.match("X-Forwarded-For: .+", request, re.IGNORECASE):
        request = re.sub(r"X-Forwarded-For: .+", "X-Forwarded-For: " + ip, request, flags=re.IGNORECASE)
    else:
        request = request.replace("User-Agent: ", "X-Forwarded-For: " + ip + "\nUser-Agent: ")
    # 伪造 client-ip
    if re.match("Client-Ip: .+", request, re.IGNORECASE):
        request = re.sub(r"Client-Ip: .+", "Client-Ip: " + ip, request, flags=re.IGNORECASE)
    else:
        request = request.replace("X-Forwarded-For: ", "Client-Ip: " + ip + "\nX-Forwarded-For: ")
    return request


# 处理User-Agent头部
def deal_http_request(request, cluster, pitchfork):
    pitchfork = get_pitchfork(cluster, pitchfork)
    request = request.format(cluster=cluster, pitchfork=pitchfork)
    request = calc_lenght(request)
    request = get_random_ip(request)
    if if_random_user_agent == 1:
        request = random_user_agent(request)
    return request


# 多线程的类,run 函数是爆破的主要处理逻辑处
class myThread (threading.Thread):
    def __init__(self, threadID, name, counter, request, pitchfork):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.request = request
        self.pitchfork = pitchfork

    def run(self):
        global clusters
        while len(clusters):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            bufsize = 10240
            s.connect((ip, port))
            cluster = clusters.pop()
            request = deal_http_request(self.request, cluster, self.pitchfork)
            s.send(request.encode("utf-8"))                             # 这个地方用笨办法重发两次
            try:
                rcv = s.recv(bufsize).decode("utf-8")
            except :
                time.sleep(2)
                s.send(request.encode("utf-8"))
                try:
                    rcv = s.recv(bufsize).decode("utf-8")
                except :
                    rcv = "error"
                    print("TimeOut Error")
            analyse_response(rcv, request, cluster)


# 入口部分
if __name__ == "__main__":
    # 一些全局变量
    request = ""
    cluster_num, pitchfork_num = 0, 0
    threads = []
    thread_num = 3
    clusters = []  # 爆破的笛卡尔积
    filenames = []
    pitchfork = []
    sleep_time = 0
    if_random_user_agent = 0
    keywords = []
    response_information = []
    response_length = {}
    ip = "127.0.0.1"
    port = 80

    # 正式操作
    print_logo()
    filename = input("输入http请求信息位置:\n")
    with open(filename, "r") as f:
        request = f.read()
    cluster_num, pitchfork_num = calc_pass_num(request)
    for i in range(cluster_num):
        filenames.append(input("请输入cluster[" + str(i) + "]的字典路径"))
    for i in range(pitchfork_num):
        pitchfork.append(int(input("请输入pitchfork[" + str(i) + "]应该等于cluster[?]:  ")))
    ip = input("请输入目标ip:")
    port = int(input("请输入目标端口号:"))
    get_choice()
    clusters = get_pass(filenames)
    # print(clusters)
    # 创建新线程
    for i in range(thread_num):
        threads.append(myThread(1, "Thread-" + str(i), i+1, request, pitchfork))

    print("开始爆破")
    for i in threads:
        i.start()
    for i in threads:
        i.join()

    for i in response_information:
        if response_length.get(i[1]) :
            response_length[i[1]] += 1
        else:
            response_length[i[1]] = 1

    result_show()
