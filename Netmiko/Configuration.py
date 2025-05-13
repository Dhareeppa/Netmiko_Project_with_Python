import MainConnection


def Connection(device_type, host, username, password, port, secret):
    Server = MainConnection.ServerConnection(device_type, host, username, password, port, secret)
    Server.Connect()
    return Server()


def Enable(Server):
    Server.EnableMode()


def Config(Server):
    Server.ConfigMode()


def CommandSending(Server, sendCmd):
    Server.sendingCommand(sendCmd)


def ConfigCommand(Server, ConfigCmd):
    Server.sendingConfigCommand(ConfigCmd)


def Closing(Server):
    Server.Close()


if __name__ == "__main__":
    device = {"device_type": "cisco_ios",
              "host": "192.168.56.5",
              "username": "router1",
              "password": "cisco",
              "port": 22,
              "secret": "lenovo"}
    Conn = Connection(**device)
    Conn.Enable()
    Conn.Config()
    cmd = "show running-config"
    Conn.ConfigSending(cmd)
    command = ["router ospf 0", "network 0.0.0.0 0.0.0.0 area 0", " network 0.0.0.0 area 0 "]
    Conn.ConfigCommand(command)
    Conn.Closwing()

