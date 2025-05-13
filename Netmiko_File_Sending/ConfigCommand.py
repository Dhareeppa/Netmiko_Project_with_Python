import MainRouter
from tkinter import messagebox
import concurrent.futures

executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)


def Connection(device_type, host, port, username, password, secret):
    Connect = MainRouter.RouterConnect(device_type, host, port, username, password, secret)
    Connect.RouterConnection()
    return Connect


def SendCmd(Connect, Cmd):
    try:
        output = Connect.CommandSend(Cmd)
        return output
    except Exception as E:
        messagebox.showerror("Error", f"{E}")
    executor.submit(SendCmd)


def UploadConfigFile(Connect, File_path):
    try:
        Connect.UploadConfigFile(File_path)
    except Exception as E:
        messagebox.showerror(f"File operation Error: ", f"{E}")

    executor.submit(UploadConfigFile)


def BackUpRunningConfig(Connect):
    try:
        name = "Running-Config"
        Commands = "show running-config"
        Connect.BackupFile(Commands, name)
    except Exception as E:
        messagebox.showerror(f"File operation Error: ", f"{E}")

    executor.submit(BackUpRunningConfig)


def BackUpStartUpConfig(Connect):
    try:
        name = "Startup-Config"
        Command = "show startup-config"
        Connect.BackupFile(Command, name)
    except Exception as E:
        messagebox.showerror(f"File operation Error:", f"{E}")

    executor.submit(BackUpStartUpConfig)


def CloseConnection(Connect):
    def close():
        Connect.ConnectionClose()

    executor.submit(close)
