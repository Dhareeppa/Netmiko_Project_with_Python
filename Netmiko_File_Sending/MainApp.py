import customtkinter as ctk
from tkinter import messagebox as m, filedialog
import ConfigCommand


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.Commands = None
        self.iconbitmap("Router.ico")
        self.title("Multiply Router Management System")
        self.geometry("1385x720")
        self.resizable(width=False, height=False)

        self.current_frame = None
        self.connected_devices = []
        self.connection = None
        self.show_frame(MainFrame)

    def show_frame(self, FrameClass):
        if self.current_frame is not None:
            self.current_frame.destroy()

        self.current_frame = FrameClass(self)
        self.current_frame.pack(fill="both", expand=True, padx=10, pady=10)

    def sendCommands(self):
        dialog = ctk.CTkInputDialog(title="Commands_Send", text="Enter the Commands:")
        self.Commands = dialog.get_input()
        return self.Commands


class MainFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.pack(fill="x", pady=10)
        self.device_entries = []

        self.user_input = ctk.CTkLabel(self.input_frame, text="Enter The Number of Devices = ")
        self.user_input.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.user_enter = ctk.CTkEntry(self.input_frame)
        self.user_enter.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        self.input_button = ctk.CTkButton(self.input_frame, text="Enter Devices",
                                          command=self.create_device_entries)
        self.input_button.grid(row=0, column=2, padx=10, pady=10)
        self.connect_button = ctk.CTkButton(self.input_frame, text="Connect", command=self.connect,
                                            font=("Arial", 12))
        self.connect_button.grid(row=0, column=3, padx=10, pady=10, sticky="w")
        self.next_button = ctk.CTkButton(self.input_frame, text="Next", command=self.next_frame,
                                         font=("Arial", 12), fg_color="green", hover_color="dark green")
        self.next_button.grid(row=0, column=4, padx=10, pady=10, sticky="w")
        self.quit_button = ctk.CTkButton(self.input_frame, text="Exit", command=self.exit, font=("Arial", 12),
                                         fg_color="red", hover_color="dark red")
        self.quit_button.grid(row=0, column=5, padx=10, pady=10, sticky="w")

        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=880, height=300)
        self.scrollable_frame.pack(fill="both", expand=True, padx=10, pady=10)

    def create_device_entries(self):
        try:
            num_devices = int(self.user_enter.get())
            if num_devices <= 0:
                raise ValueError("Number of devices must be positive")
        except ValueError as e:
            m.showerror("Error", f"Invalid input: {str(e)}. Please enter a positive number.")
            return

        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.device_entries.clear()

        for i in range(num_devices):
            device_frame = ctk.CTkFrame(self.scrollable_frame)
            device_frame.pack(fill="x", padx=5, pady=5)

            labels = ["Device Type", "Hostname", "Port", "Username", "Password", "Secret"]
            entries = []

            for j, label in enumerate(labels):
                ctk.CTkLabel(device_frame, text=f"{label} {i + 1}:", font=("Arial", 12)).grid(row=0, column=j * 2,
                                                                                              padx=5, pady=5,
                                                                                              sticky="w")
                if label in ["Password", "Secret"]:

                    entry = ctk.CTkEntry(device_frame, show="*")
                else:
                    entry = ctk.CTkEntry(device_frame)
                entry.grid(row=0, column=j * 2 + 1, padx=5, pady=5, sticky="w")
                entries.append(entry)
            self.device_entries.append({
                "device_type": entries[0],
                "ip": entries[1],
                "port": entries[2],
                "username": entries[3],
                "password": entries[4],
                "secret": entries[5]
            })

    def connect(self):
        connected_ips = []
        for i, entry in enumerate(self.device_entries):
            device_type = entry["device_type"].get()
            router_ip = entry["ip"].get()
            port = entry["port"].get()
            username = entry["username"].get()
            password = entry["password"].get()
            secret = entry["secret"].get()
            try:
                connect_obj = ConfigCommand.Connection(device_type, router_ip, port, username, password, secret)
                if connect_obj:
                    connected_ips.append(router_ip)
                    self.parent.connected_devices.append({
                        "device_type": device_type,
                        "ip": router_ip,
                        "port": port,
                        "username": username,
                        "password": password,
                        "secret": secret
                    })
            except Exception as e:
                m.showerror("Connection Error", f"Failed to connect to {router_ip}: {str(e)}")

        if connected_ips:
            m.showinfo("Connection Status", f"Connected to devices: {', '.join(connected_ips)}")
        else:
            m.showinfo("Connection Status", "Failed to connect to any devices.")

    def exit(self):
        if self.parent.connection:
            self.parent.connection.CloseConnection()
        self.parent.quit()

    def next_frame(self):
        self.parent.show_frame(NextFrame)


class NextFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.view = None
        self.parent = parent

        self.header = ctk.CTkLabel(self, text="-: Select The Connected Routers :-", font=("Arial", 18))
        self.header.grid(row=0, column=0, padx=10, pady=10)
        self.Back = ctk.CTkButton(self, text="Back", command=self.back_to_main, font=("Arial", 12))
        self.Back.grid(row=0, column=1, padx=10, pady=10)
        self.Exit = ctk.CTkButton(self, text="Exit", command=self.exit, font=("Arial", 12), fg_color="red",
                                  hover_color="dark red")
        self.Exit.grid(row=0, column=2, padx=10, pady=10)

        self.checkboxes = []
        self.perform_buttons = []

        for i, host in enumerate(self.parent.connected_devices):
            check_var = ctk.BooleanVar()
            checkBox = ctk.CTkCheckBox(self, text=host["ip"], variable=check_var)
            checkBox.grid(row=i + 1, column=0, padx=10, pady=10)
            self.checkboxes.append((checkBox, host))

            upload_button = ctk.CTkButton(self, text="Upload Config File",
                                          command=self.UploadConfigFile,
                                          fg_color="green", hover_color="dark green")
            upload_button.grid(row=i + 1, column=1, padx=10, pady=10)
            self.perform_buttons.append(upload_button)

            backup_running_button = ctk.CTkButton(self, text="BackUpRunningConfig",
                                                  command=self.BackupRunningConfig)
            backup_running_button.grid(row=i + 1, column=2, padx=10, pady=10)
            self.perform_buttons.append(backup_running_button)

            backup_startup_button = ctk.CTkButton(self, text="BackUpStartupConfig",
                                                  command=self.BackupStartupConfig)
            backup_startup_button.grid(row=i + 1, column=3, padx=10, pady=10)
            self.perform_buttons.append(backup_startup_button)

            preview = ctk.CTkButton(self, text="View", command=self.Send)
            preview.grid(row=i + 1, column=4, padx=10, pady=10)
            self.perform_buttons.append(backup_startup_button)

    def exit(self):
        if self.parent.connection:
            self.parent.connection.CloseConnection()
        self.parent.quit()

    def back_to_main(self):
        self.parent.show_frame(MainFrame)

    def get_selected_devices(self):
        return [host for checkBox, host in self.checkboxes if checkBox.get()]

    def Send(self):
        selected_devices = self.get_selected_devices()
        Command = self.parent.sendCommands()
        if not selected_devices:
            m.showinfo("Error", "Please select at least one router.")
            return
        for host in selected_devices:
            connection = ConfigCommand.Connection(host["device_type"], host["ip"], host["port"],
                                                  host["username"], host["password"], host["secret"])
            if connection:
                try:
                    output = ConfigCommand.SendCmd(connection, Command)
                    return output
                except Exception as e:
                    m.showerror("Error", f"Failed to upload config file to {host['ip']}: {str(e)}")
            else:
                m.showerror("Connection Error", f"Unable to connect to {host['ip']}.")

    def UploadConfigFile(self):
        file_path = filedialog.askopenfilename(title="Select Configuration File",
                                               filetypes=(("Config files", "*.cfg *.txt"), ("All files", "*.*")))
        if not file_path:
            m.showerror("Error", "No file selected!")
            return

        selected_devices = self.get_selected_devices()

        if not selected_devices:
            m.showinfo("Error", "Please select at least one router.")
            return

        for host in selected_devices:
            connection = ConfigCommand.Connection(host["device_type"], host["ip"], host["port"],
                                                  host["username"], host["password"], host["secret"])
            if connection:
                try:
                    ConfigCommand.UploadConfigFile(connection, file_path)
                    m.showinfo("Success", f"File uploaded to {host['ip']} successfully!")
                except Exception as e:
                    m.showerror("Error", f"Failed to upload config file to {host['ip']}: {str(e)}")
            else:
                m.showerror("Connection Error", f"Unable to connect to {host['ip']}.")

    def BackupRunningConfig(self):
        selected_devices = self.get_selected_devices()
        if not selected_devices:
            m.showinfo("Error", "Please select at least one router.")
            return

        for host in selected_devices:
            connection = ConfigCommand.Connection(host["device_type"], host["ip"], host["port"],
                                                  host["username"], host["password"], host["secret"])
            if connection:
                try:
                    ConfigCommand.BackUpRunningConfig(connection)
                    m.showinfo("Success", f"Running config backed up for {host['ip']} successfully!")
                except Exception as e:
                    m.showerror("Error", f"Failed to back up running config for {host['ip']}: {str(e)}")
            else:
                m.showerror("Connection Error", f"Unable to connect to {host['ip']}.")

    def BackupStartupConfig(self):
        selected_devices = self.get_selected_devices()
        if not selected_devices:
            m.showinfo("Error", "Please select at least one router.")
            return

        for host in selected_devices:
            connection = ConfigCommand.Connection(host["device_type"], host["ip"], host["port"],
                                                  host["username"], host["password"], host["secret"])
            if connection:
                try:
                    ConfigCommand.BackUpStartUpConfig(connection)
                    m.showinfo("Success", f"Startup config backed up for {host['ip']} successfully!")
                except Exception as e:
                    m.showerror("Error", f"Failed to back up startup config for {host['ip']}: {str(e)}")
            else:
                m.showerror("Connection Error", f"Unable to connect to {host['ip']}.")


if __name__ == "__main__":
    app = App()
    app.mainloop()
