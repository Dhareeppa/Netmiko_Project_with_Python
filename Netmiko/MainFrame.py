import customtkinter as ctk


# import tkinter.messagebox as m


class RemoteSoft(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("700x500")
        self.title("RemoteTerminal-Manager")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.current_frame = None

    def show_frame(self, FrameClass):
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = FrameClass(self)
        self.current_frame.grid(row=0, column=0, padx=(20, 20), pady=(10, 10), sticky="nsew")


class MainFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent


if __name__ == "__main__":
    app = RemoteSoft()
    app.mainloop()
