from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from netmiko import ConnectHandler


class ServerConnection:
    def __init__(self, device_type, host, username, password, port, secret, verbose=True):
        self.device_type = device_type
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.secret = secret
        self.verbose = verbose
        self.Connect = None

    def ConnectToServer(self):
        try:
            self.Connect = ConnectHandler(device_type=self.device_type, host=self.host, username=self.username,
                                          password=self.password, port=self.port, secret=self.secret)
            print("Connection is successfully...")
        except NetmikoAuthenticationException:
            print("Authentication Error: Password Incorrect.")
        except NetmikoTimeoutException:
            print("Connection Timeout: Unable to connect to the device.")
        except Exception as e:
            print(f"Operation Error: {e}")

    def EnableMode(self):
        self.Connect.enable()
        print("Entering Enable Mode...")

    def ConfigMode(self):
        try:
            self.Connect.config_mode()
            print("Entering Config Mode....")
        except Exception as e:
            print(f"Failed to enter global configuration mode: {e}")

    def sendingCommand(self, EnableCommands):
        try:
            output = self.Connect.send_command(EnableCommands)
            print(f"Command: {EnableCommands}\noutput{output}")
            return output
        except Exception as e:
            print(f"Command execution failed: {e}")

    def sendingConfigCommand(self, ConfigCommands):
        try:
            output = self.Connect.send_config_set(ConfigCommands)
            print(f"Command: {ConfigCommands}\noutput{output}")
            return output
        except Exception as e:
            print(f"Command execution failed: {e}")

    def Close(self):
        self.Connect.disconnect()
        print("Connection closed.....")


if __name__ == "__main__":
    device1 = {
        'device_type': 'cisco_ios',
        'host': '192.168.56.5',
        'username': 'router1',
        'password': 'cisco',
        "port": "22",
        'secret': 'lenovo',
        'verbose': True
    }

    connection = ServerConnection(**device1)
    connection.ConnectToServer()
    connection.EnableMode()
    connection.ConfigMode()

    commands = ["interface loopback 0",
                "ip address 1.1.1.1 255.255.255.255",
                "shutdown",
                "exit",
                "username netmiko secret password",
                "end"]
    connection.sendingConfigCommand(commands)
    showInterface = "show running-config | include username"
    connection.sendingCommand(showInterface)
    connection.Close()
