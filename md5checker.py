import tkinter


class Gui(tkinter.Tk):
    """
    Handles behavior for all GUI elements. Nothing all that interesting here.
    """
    if __name__ == "__main__":
        def __init__(self):
            super(Gui, self).__init__()
            self.title("File Integrity Verification Tool")
            self.minsize(525, 225)
            self.resizable(False, False)
            self.task = tkinter.IntVar()
            self.task.set(2)
            self.label = tkinter.Label(self, text="Select a task below: ")
            self.button1 = tkinter.Radiobutton(text="Generate MD5 Hash",
                                               variable=self.task, value=1,
                                               command=self.generate_view)
            self.button2 = tkinter.Radiobutton(
                text="Check File Against Provided MD5", variable=self.task,
                value=2, command=self.verify_view)
            self.button3 = tkinter.Radiobutton(text="Compare MD5 Strings",
                                               variable=self.task, value=3,
                                               command=self.compare_view)
            self.quit_button = tkinter.Button(text="Quit",
                                              command=self.destroy)
            self.hash_value = tkinter.StringVar()
            self.vendor_value = tkinter.StringVar()
            self.hash_input_label = tkinter.Label(
                text="Enter your pre-generated MD5 hash here:")
            self.hash_input = tkinter.Entry(width=32,
                                            textvariable=self.hash_value)
            self.vendor_hash_label = tkinter.Label(
                text="Enter the vendor-provided md5 hash here:")
            self.vendor_input = tkinter.Entry(width=32,
                                              textvariable=self.vendor_value)
            self.compare_button = tkinter.Button(
                text="Compare", command=lambda: compare_button_action(
                    self.hash_value.get(), self.vendor_value.get()))
            self.verify_button = tkinter.Button(
                text="Verify", command=lambda: verify_button_action(
                    self.file_path.get(), self.vendor_value.get()))
            self.generate_button = tkinter.Button(
                text="Generate", command=lambda: generate_button_action(
                    self.file_path.get()))
            self.generate_bottom = tkinter.Label(text="Compare this to "
                                                      "the vendor's MD5 hash.")
            self.generate_bottom2 = tkinter.Label(text="The hashes should "
                                                       "match.")
            self.result_label = tkinter.Label(text="Result:")
            self.result_text = tkinter.StringVar()
            self.process_result = tkinter.Label(textvariable=self.result_text)
            self.result_field = tkinter.LabelFrame(text=self.result_text)
            self.result_field_cp = tkinter.Entry(width=32,
                                                 textvariable=self.result_text)
            self.file_path = tkinter.StringVar()
            self.file_input = tkinter.Entry(textvariable=self.file_path)
            self.file_label = tkinter.Label(text="Enter file path or click "
                                                 "the Browse button.")
            self.browse_button = tkinter.Button(text="Browse",
                                                command=self.browse_files)
            # This has to be at the end of the init method.
            self.verify_view()
            self.create_ui()

        def create_ui(self):
            """
            Builds base GUI elements.
            """
            self.label.grid(column=0, row=0, columnspan=3, sticky='nsew')
            self.button1.grid(column=0, row=1, sticky='nsew')
            self.button2.grid(column=1, row=1, sticky='nsew')
            self.button3.grid(column=2, row=1, sticky='nsew')
            self.browse_button.grid(column=2, row=4, sticky='nsew', padx=5)
            self.quit_button.grid(column=2, row=10, sticky='nsew')

        def verify_view(self):
            """
            Loads GUI elements to allow a user to verify a file against a
            known MD5 hash.
            """
            self.cleanup()
            self.file_label.grid(column=1, row=3, sticky='nsew')
            self.file_input.grid(column=1, row=4, sticky='nsew', ipady=5)
            self.browse_button.config(state="normal")
            self.vendor_hash_label.grid(column=1, row=5)
            self.vendor_input.grid(column=1, row=7, sticky='nsew', ipady=5)
            self.result_label.grid(column=1, row=8)
            self.process_result.grid(column=1, row=9, sticky='nsew')
            self.verify_button.grid(column=1, row=10, sticky='nsew')

        def generate_view(self):
            """
            Loads GUI elements to allow a user to generate a MD5 hash for the
            specified file.
            """
            self.cleanup()
            self.file_label.grid(column=1, row=3, sticky='nsew')
            self.file_input.grid(column=1, row=4, sticky='nsew', ipadx=15,
                                 ipady=5)
            self.browse_button.config(state="normal")
            # padx has to be 94 here to keep the window contents from shifting
            # when moving between tasks.
            self.result_label.grid(column=1, row=6, padx=94)
            self.result_field_cp.grid(column=1, row=7, sticky='nsew', ipadx=15,
                                      ipady=5)
            self.generate_bottom.grid(column=1, row=8)
            self.generate_bottom2.grid(column=1, row=9)
            self.generate_button.grid(column=1, row=10, sticky='nsew')

        def compare_view(self):
            """
            Loads GUI elements to allow a user to compare two MD5 strings.
            """
            self.cleanup()
            self.hash_input_label.grid(column=1, row=3, sticky='nsew')
            self.browse_button.config(state="disabled")
            self.hash_input.grid(column=1, row=4, ipadx=15, sticky='nsew',
                                 ipady=5)
            self.vendor_hash_label.grid(column=1, row=5)
            self.vendor_input.grid(column=1, row=6, sticky='nsew', ipadx=15,
                                   ipady=5)
            self.result_label.grid(column=1, row=7)
            self.process_result.grid(column=1, row=9, sticky='nsew')
            self.compare_button.grid(column=1, row=10, sticky='nsew')

        def browse_files(self):
            """
            Creates a file selection dialogue box, starting in the user's
            current directory. The selected file is stored as file_name (str)
            :return:
            Returns file_name (str) which is the full file path of the user
            specified file.
            """
            from tkinter import filedialog
            from os import getcwd
            directory = getcwd
            file_name = filedialog.askopenfilename(
                initialdir=directory, title="Select a File",
                filetypes=(("Binary files", "*.bin"), ("all files", "*.*")))
            self.file_path.set(file_name)
            return file_name

        def cleanup(self):
            """
            Remove view-specific widgets. This function will be called by the
            view creation functions prior to loading their own widgets.
            """
            self.compare_button.grid_forget()
            self.generate_button.grid_forget()
            self.verify_button.grid_forget()
            self.file_label.grid_forget()
            self.file_input.grid_forget()
            self.hash_input_label.grid_forget()
            self.hash_input.grid_forget()
            self.vendor_hash_label.grid_forget()
            self.vendor_input.grid_forget()
            self.result_label.grid_forget()
            self.result_field.grid_forget()
            self.process_result.grid_forget()
            self.result_field_cp.grid_forget()
            self.generate_bottom.grid_forget()
            self.generate_bottom2.grid_forget()
            self.result_text.set("")
            self.hash_value.set("")
            self.vendor_value.set("")
            self.file_path.set("")

    else:
        print("Can't call this class or its methods externally.")


def calculate_hash(file):
    """
    Opens the user-specified file and calculates its MD5 hash.
    :param file: file path passed to the function as type str
    :return: Returns md5_value (str), which is the MD5 hash of the file.
    """
    from hashlib import md5
    with open(file, "rb") as hashed_file:
        data = hashed_file.read()
        md5_value = md5(data).hexdigest()
        return md5_value


def compare_hash(md5_result, input_hash):
    """
    Compares two user-specified strings to see if they match.
    :param md5_result: First user-specified MD5 hash (str)
    :param input_hash: Second user-specified MD5 hash (str)
    :return: Returns file_integrity (bool)
    """
    if md5_result == input_hash:
        file_integrity = True
    else:
        file_integrity = False
    return file_integrity


def verify_input(input_hash):
    """
    Verifies that the user-specified input fits the formatting of an MD5 hash,
    32 characters long and hexadecimal formatting.
    :param input_hash: User-specified MD5 hash (str)
    :return: Returns verification (bool)
    """
    from re import match
    if len(input_hash) != 32:
        verification = False
        return verification
    else:
        if match("^[a-f0-9]*$", input_hash):
            verification = True
            return verification
        else:
            verification = False
            return verification


def compare_button_action(hash1, hash2):
    """
    Called when the user clicks the "Compare" button in the GUI. Verifies that
    the hashes provided are the same. Updates the gui.result_text variable with
     the result of the comparison. Can't be called externally.
    :param hash1: Passed from the GUI as hash_value (str)
    :param hash2: Passed from the GUI as vendor_value (str)
    """
    if __name__ == "__main__":
        verified_hash1 = verify_input(hash1)
        verified_hash2 = verify_input(hash2)
        if verified_hash1 and verified_hash2 is True:
            if hash1 == hash2:
                gui.result_text.set("Hashes match.")
            else:
                gui.result_text.set("Hashes don't match.")
        else:
            gui.result_text.set("Hash format invalid.")
    else:
        print("Can't be called externally.")


def verify_button_action(file, hash_value):
    """
    Called when the user clicks the "Verify" button in the GUI. Generates a MD5
    hash for the file specified. The resulting hash is compared against the
    provided MD5 hash to ensure the file is not corrupt. The gui.result_text
    variable is updated with the result of the comparison. Can't be called
    externally.
    :param file: Passed from GUI as file_path (str)
    :param hash_value: Passed from GUI as vendor_value (str)
    """
    if __name__ == "__main__":
        try:
            md5 = calculate_hash(file)
            verified_hash = verify_input(hash_value)
            if verified_hash is True:
                if hash_value == md5:
                    gui.result_text.set("File is valid.")
                else:
                    gui.result_text.set("File does not match checksum. "
                                        "Do not use.")
            else:
                gui.result_text.set("Hash format invalid.")
        except FileNotFoundError:
            gui.result_text.set("File not found.")
    else:
        print("Can't be called externally.")


def generate_button_action(file):
    """
    Called when the user clicks the "Generate" button in the GUI. Generates a
    MD5 hash for the file specified. The gui.result_text variable is updated
    with the MD5 hash. Can't be called externally.
    :param file: Passed from the GUI as file_path (str)
    """
    if __name__ == "__main__":
        try:
            md5 = calculate_hash(file)
            gui.result_text.set(md5)
        except FileNotFoundError:
            gui.result_text.set("File not found.")
    else:
        print("Can't be called externally.")


# Builds GUI
gui = Gui()
gui.mainloop()
