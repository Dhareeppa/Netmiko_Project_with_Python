import datetime
from netmiko import ConnectHandler
from netmiko import ConnectionException, NetmikoAuthenticationException, NetmikoTimeoutException
from tkinter import messagebox as m
import time
import threading


class RouterConnect:
    def __init__(self, device_type, host, port, username, password, secret=None, verbose=True):
        self.device_type = device_type
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.secret = secret
        self.verbose = verbose
        self.Connect = None

    def RouterConnection(self):
        try:
            connection_params = {
                'device_type': self.device_type,
                'host': self.host,
                'port': self.port,
                'username': self.username,
                'password': self.password,
                'secret': self.secret,
                'verbose': self.verbose
            }
            self.Connect = ConnectHandler(**connection_params)
        except ConnectionException as Conn:
            m.showerror(f"Connection Error: ", f"{Conn}")
        except NetmikoAuthenticationException as auth:
            m.showerror(f"Authentication Error: ", f"{auth}")
        except NetmikoTimeoutException as T:
            m.showerror(f"TimeOut Error:", f"{T}")

    def CommandSend(self, cmd):
        self.Connect.enable()
        output = self.Connect.send_command(cmd)
        m.showinfo("Information", f"{output}")

    def UploadConfigFile(self, fileName):
        self.Connect.enable()
        output = self.Connect.send_config_from_file(fileName)
        print(output)
        print(f"Config Successfully {self.host}..")
        print("#" * 30)

    def BackupFile(self, Command, Name):
        self.Connect.enable()
        output = self.Connect.send_command(Command)
        prompt = self.Connect.find_prompt()
        hostname = prompt[0:-1]
        now = datetime.datetime.now()
        year = now.year
        month = now.month
        day = now.day

        FileName = f"{hostname}-Y{year}-M{month}-D{day}-{Name}"
        with open(FileName, "w") as backup:
            backup.write(output)
        m.showinfo("Backup successfully ", f"backup Successfully: {hostname} Completed..")
        print("#" * 30)

    def ConnectionClose(self):
        self.Connect.disconnect()
        m.showinfo(f"Connection", f"Connection disconnect{self.host}")


if __name__ == "__main__":
    Device_type = input("Enter Device_type: ")
    ip = input("Enter IP ADDRESS: ")
    Port = input("Enter Port: ")
    UserName = input("Enter UserName: ")
    Password = input("Enter Password: ")
    Secret = input("Enter Secret Password: ")

    devices = [
        {"device_type": Device_type, "host": ip, "port": Port, "username": UserName, "password": Password,
         "secret": Secret}
    ]

    threads = []
    start_time = time.time()
    router = None

    for device_info in devices:
        router = RouterConnect(**device_info)
        th = threading.Thread(target=router.RouterConnection)
        threads.append(th)
        th.start()

    for th in threads:
        th.join()

    end_time = time.time()
    print(f"Total Execution Time: {end_time - start_time} seconds")

    Config_file = input("Enter the Config-File Path: ")
    if Config_file:
        router.UploadConfigFile(Config_file)

    backup_file = input("Enter the Backup Command: ")
    name = input("Enter file name")
    if backup_file:
        router.BackupFile(backup_file, name)
    command = input("Enter tha Command : ")
    if command:
        router.CommandSend(command)

    if router:
        router.ConnectionClose()
