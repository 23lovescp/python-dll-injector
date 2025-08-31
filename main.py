import tkinter as tk
from tkinter import ttk, filedialog
import os
import threading
import time
import ctypes
import psutil
import random
import base64
import zlib
import hashlib
import platform
import socket
import win32api
import win32con
import win32process
import win32gui

class InjectionThread(threading.Thread):
    def __init__(self, method, pid, dll_path, key):
        super().__init__()
        self.method = method
        self.pid = pid
        self.dll_path = dll_path
        self.key = key
        self.success = False
        self.err = ""

        
    def run(self):
        self.success = self.inject()
        if self.success:
            root.event_generate("<<InjectionSuccess>>", when="tail")
        else:
            root.event_generate("<<InjectionFailed>>", when="tail")

    def inject(self):
        kernel32 = ctypes.windll.kernel32
        try:
            proc = kernel32.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, self.pid)
            if not proc:
                self.err = "Failed to open process handle"
                return False
            dll_data = self.layerobf_data(open(self.dll_path, "rb").read(), self.key)
            alloc_addr = kernel32.VirtualAllocEx(proc, 0, len(dll_data), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_EXECUTE_READWRITE)
            if not alloc_addr:
                self.err = "Memory allocation failed"
                return False
            written = ctypes.c_size_t()
            if not kernel32.WriteProcessMemory(proc, alloc_addr, dll_data, len(dll_data), ctypes.byref(written)):
                self.err = "Write process memory failed"
                return False
            if self.method == "manual map":
                thread_id = ctypes.c_ulong()
                thread = kernel32.CreateRemoteThread(proc, None, 0, alloc_addr, 0, 0, ctypes.byref(thread_id))
                if thread:
                    kernel32.WaitForSingleObject(thread, win32con.INFINITE)
                    kernel32.CloseHandle(thread)
            elif self.method == "load library":
                dll_path_obf = self.layerobf(self.dll_path, self.key)
                alloc_addr = kernel32.VirtualAllocEx(proc, 0, len(dll_path_obf), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_READWRITE)
                if not alloc_addr:
                    self.err = "Memory allocation failed"
                    return False
                written = ctypes.c_size_t()
                if not kernel32.WriteProcessMemory(proc, alloc_addr, dll_path_obf.encode(), len(dll_path_obf), ctypes.byref(written)):
                    self.err = "Write process memory failed"
                    return False
                loadlib_addr = kernel32.GetProcAddress(kernel32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA")
                thread_id = ctypes.c_ulong()
                thread = kernel32.CreateRemoteThread(proc, None, 0, loadlib_addr, alloc_addr, 0, ctypes.byref(thread_id))
                if thread:
                    kernel32.WaitForSingleObject(thread, win32con.INFINITE)
                    kernel32.CloseHandle(thread)
            elif self.method == "apc injection":
                dll_path_obf = self.layerobf(self.dll_path, self.key)
                alloc_addr = kernel32.VirtualAllocEx(proc, 0, len(dll_path_obf), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_READWRITE)
                if not alloc_addr:
                    self.err = "Memory allocation failed"
                    return False
                written = ctypes.c_size_t()
                if not kernel32.WriteProcessMemory(proc, alloc_addr, dll_path_obf.encode(), len(dll_path_obf), ctypes.byref(written)):
                    self.err = "Write process memory failed"
                    return False
                loadlib_addr = kernel32.GetProcAddress(kernel32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA")
                threads = [t for t in psutil.Process(self.pid).threads()]
                for thread in threads[:1]:
                    th_handle = kernel32.OpenThread(win32con.THREAD_ALL_ACCESS, False, thread.id)
                    if th_handle:
                        kernel32.QueueUserAPC(loadlib_addr, th_handle, alloc_addr)
                        kernel32.CloseHandle(th_handle)
            elif self.method == "thread hijacking":
                threads = [t for t in psutil.Process(self.pid).threads()]
                if not threads:
                    self.err = "No threads found"
                    return False
                target_id = threads[0].id
                target = kernel32.OpenThread(win32con.THREAD_ALL_ACCESS, False, target_id)
                if not target:
                    self.err = "Failed to open thread"
                    return False
                context = ctypes.create_string_buffer(0x2CC)
                if not kernel32.GetThreadContext(target, ctypes.byref(context)):
                    self.err = "Failed to get thread context"
                    return False
                dll_path_obf = self.layerobf(self.dll_path, self.key)
                alloc_addr = kernel32.VirtualAllocEx(proc, 0, len(dll_path_obf), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_READWRITE)
                if not alloc_addr:
                    self.err = "Memory allocation failed"
                    return False
                written = ctypes.c_size_t()
                if not kernel32.WriteProcessMemory(proc, alloc_addr, dll_path_obf.encode(), len(dll_path_obf), ctypes.byref(written)):
                    self.err = "Write process memory failed"
                    return False
                loadlib_addr = kernel32.GetProcAddress(kernel32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA")
                context_addr = ctypes.c_void_p.from_buffer(context).value + 0xB8
                kernel32.WriteProcessMemory(proc, context_addr, ctypes.byref(ctypes.c_void_p(loadlib_addr)), ctypes.sizeof(ctypes.c_void_p), None)
                kernel32.SetThreadContext(target, ctypes.byref(context))
                kernel32.ResumeThread(target)
                time.sleep(0.1)
            elif self.method == "ref dll":
                dll_data = self.layerobf_data(open(self.dll_path, "rb").read(), self.key)
                alloc_addr = kernel32.VirtualAllocEx(proc, 0, len(dll_data), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_EXECUTE_READWRITE)
                if not alloc_addr:
                    self.err = "Memory allocation failed"
                    return False
                written = ctypes.c_size_t()
                if not kernel32.WriteProcessMemory(proc, alloc_addr, dll_data, len(dll_data), ctypes.byref(written)):
                    self.err = "Write process memory failed"
                    return False
                reflective_loader = self.generate_reflective_loader()
                loader_addr = kernel32.VirtualAllocEx(proc, 0, len(reflective_loader), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_EXECUTE_READWRITE)
                if not loader_addr:
                    self.err = "Loader allocation failed"
                    return False
                written = ctypes.c_size_t()
                if not kernel32.WriteProcessMemory(proc, loader_addr, reflective_loader, len(reflective_loader), ctypes.byref(written)):
                    self.err = "Write loader memory failed"
                    return False
                thread_id = ctypes.c_ulong()
                thread = kernel32.CreateRemoteThread(proc, None, 0, loader_addr, alloc_addr, 0, ctypes.byref(thread_id))
                if thread:
                    kernel32.WaitForSingleObject(thread, win32con.INFINITE)
                    kernel32.CloseHandle(thread)
            elif self.method == "early bird":
                h_proc = win32api.OpenProcess(win32con.PROCESS_CREATE_THREAD | win32con.PROCESS_VM_OPERATION | win32con.PROCESS_VM_WRITE, False, self.pid)
                if not h_proc:
                    self.err = "Failed to open process for early injection"
                    return False
                dll_path_obf = self.layerobf(self.dll_path, self.key)
                alloc_addr = kernel32.VirtualAllocEx(h_proc, 0, len(dll_path_obf), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_READWRITE)
                if not alloc_addr:
                    self.err = "Memory allocation failed"
                    return False
                written = ctypes.c_size_t()
                if not kernel32.WriteProcessMemory(h_proc, alloc_addr, dll_path_obf.encode(), len(dll_path_obf), ctypes.byref(written)):
                    self.err = "Write process memory failed"
                    return False
                h_thread = win32process.CreateRemoteThread(h_proc, None, 0, kernel32.GetProcAddress(kernel32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA"), alloc_addr, 0)
                if h_thread:
                    win32api.WaitForSingleObject(h_thread, win32con.INFINITE)
                    win32api.CloseHandle(h_thread)
                win32api.CloseHandle(h_proc)
            elif self.method == "remote thread":
                dll_path_obf = self.layerobf(self.dll_path, self.key)
                alloc_addr = kernel32.VirtualAllocEx(proc, 0, len(dll_path_obf), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_READWRITE)
                if not alloc_addr:
                    self.err = "Memory allocation failed"
                    return False
                written = ctypes.c_size_t()
                if not kernel32.WriteProcessMemory(proc, alloc_addr, dll_path_obf.encode(), len(dll_path_obf), ctypes.byref(written)):
                    self.err = "Write process memory failed"
                    return False
                loadlib_addr = kernel32.GetProcAddress(kernel32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA")
                thread_id = ctypes.c_ulong()
                thread = kernel32.CreateRemoteThread(proc, None, 0, loadlib_addr, alloc_addr, 0, ctypes.byref(thread_id))
                if thread:
                    kernel32.WaitForSingleObject(thread, win32con.INFINITE)
                    kernel32.CloseHandle(thread)
            elif self.method == "process hollowing":
                dll_path_obf = self.layerobf(self.dll_path, self.key)
                alloc_addr = kernel32.VirtualAllocEx(proc, 0, len(dll_path_obf), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_READWRITE)
                if not alloc_addr:
                    self.err = "Memory allocation failed"
                    return False
                written = ctypes.c_size_t()
                if not kernel32.WriteProcessMemory(proc, alloc_addr, dll_path_obf.encode(), len(dll_path_obf), ctypes.byref(written)):
                    self.err = "Write process memory failed"
                    return False
                loadlib_addr = kernel32.GetProcAddress(kernel32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA")
                thread_id = ctypes.c_ulong()
                thread = kernel32.CreateRemoteThread(proc, None, 0, loadlib_addr, alloc_addr, 0, ctypes.byref(thread_id))
                if thread:
                    kernel32.WaitForSingleObject(thread, win32con.INFINITE)
                    kernel32.CloseHandle(thread)
            elif self.method == "shellcode_injection":
                dll_data = self.layerobf_data(open(self.dll_path, "rb").read(), self.key)
                alloc_addr = kernel32.VirtualAllocEx(proc, 0, len(dll_data), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_EXECUTE_READWRITE)
                if not alloc_addr:
                    self.err = "Memory allocation failed"
                    return False
                written = ctypes.c_size_t()
                if not kernel32.WriteProcessMemory(proc, alloc_addr, dll_data, len(dll_data), ctypes.byref(written)):
                    self.err = "Write process memory failed"
                    return False
                thread_id = ctypes.c_ulong()
                thread = kernel32.CreateRemoteThread(proc, None, 0, alloc_addr, 0, 0, ctypes.byref(thread_id))
                if thread:
                    kernel32.WaitForSingleObject(thread, win32con.INFINITE)
                    kernel32.CloseHandle(thread)
            elif self.method == "setwindows hook":
                dll_path_obf = self.layerobf(self.dll_path, self.key)
                alloc_addr = kernel32.VirtualAllocEx(proc, 0, len(dll_path_obf), win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_READWRITE)
                if not alloc_addr:
                    self.err = "Memory allocation failed"
                    return False
                written = ctypes.c_size_t()
                if not kernel32.WriteProcessMemory(proc, alloc_addr, dll_path_obf.encode(), len(dll_path_obf), ctypes.byref(written)):
                    self.err = "Write process memory failed"
                    return False
                user32 = ctypes.windll.user32
                hook_addr = user32.SetWindowsHookExA(1, alloc_addr, 0, self.pid)
                if hook_addr:
                    user32.UnhookWindowsHookEx(hook_addr)
            kernel32.VirtualFreeEx(proc, alloc_addr, 0, win32con.MEM_RELEASE)
            kernel32.CloseHandle(proc)
            return True
        except Exception as e:
            self.err = str(e)
            return False
    def layerobf(self, path, key):
        encoded = base64.b64encode(zlib.compress(path.encode())).decode()
        return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(encoded, hashlib.sha256(key).hexdigest()[:len(encoded)]))
    def layerobf_data(self, data, key):
        encoded = base64.b64encode(zlib.compress(data))
        return bytes(a ^ b for a, b in zip(encoded, hashlib.sha256(key).digest() * (len(encoded) // 32 + 1)))
    def generate_reflective_loader(self):
        return bytes([0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56, 0x57, 0x8B, 0xF1])

class DLLInjector:
    def __init__(self, root):
        self.root = root
        self.root.title("Lokalisering Injector")
        self.root.geometry("600x500+200+200")
        self.root.configure(bg="#2E2E2E")
        accent = "#%06x" % random.randint(0x000000, 0xCCCCCC)
        text = "#FFFFFF"
        tk.Label(root, text="Lokalisering Injector", font=("Arial", 18, "bold"), fg=accent, bg="#2E2E2E").place(relx=0.5, rely=0.02, anchor="center")
        frame1 = ttk.Frame(root)
        frame1.place(relx=0.5, rely=0.15, anchor="center")
        proc_list = tk.Listbox(frame1, width=50, height=10, bg="#333333", fg=text, selectmode=tk.MULTIPLE)
        self.autoproclist(proc_list)
        frame2 = ttk.Frame(root)
        frame2.place(relx=0.5, rely=0.45, anchor="center")
        ttk.Label(frame2, text="DLL Path:").grid(row=0, column=0, padx=5, pady=5)
        path_var = tk.StringVar(value="No file selected")
        dll_text = tk.Entry(frame2, textvariable=path_var, bg="#333333", fg=text, width=40)
        dll_text.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame2, text="Add DLL", command=lambda: self.dllbrowse(path_var, dll_text)).grid(row=0, column=2, padx=5, pady=5)
        frame3 = ttk.Frame(root)
        frame3.place(relx=0.5, rely=0.55, anchor="center")
        ttk.Label(frame3, text="Method:").grid(row=0, column=0, padx=5, pady=5)
        method_var = tk.StringVar(value="manual map")
        method_combo = ttk.Combobox(frame3, textvariable=method_var, values=["manual map", "load library", "apc injection", "thread hijacking", "ref dll", "early bird", "remote thread", "process hollowing", "shellcode_injection", "setwindows hook"], state="readonly", width=30)
        method_combo.grid(row=0, column=1, padx=5, pady=5)
        frame4 = ttk.Frame(root)
        frame4.place(relx=0.5, rely=0.65, anchor="center")
        proc_var = tk.StringVar(value="No proc selected")
        proc_text = tk.Entry(frame4, textvariable=proc_var, bg="#333333", fg=text, width=40)
        proc_text.grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(frame4, text="Select", command=lambda: self.openproc(proc_var, proc_list)).grid(row=0, column=1, padx=5, pady=5)
        status_var = tk.StringVar()
        ttk.Label(root, textvariable=status_var, font=("Arial", 12, "bold")).place(relx=0.5, rely=0.75, anchor="center")
        log_text = tk.Text(root, width=60, height=6, bg="#333333", fg=text, state="disabled")
        log_text.place(relx=0.5, rely=0.85, anchor="center")
        ttk.Button(root, text="Inject", command=lambda: self.inject(method_var, path_var, proc_list, log_text, status_var, proc_var), width=15).place(relx=0.5, rely=0.95, anchor="center")
        style = ttk.Style()
        style.configure("Accent.TButton", foreground="white", background=accent)
        style.map("Accent.TButton", background=[("active", "#%06x" % (int(accent[1:], 16) - 0x101010))])
        self.key = os.urandom(16)
        if self.vmenvdetector():
            self.log(log_text, f"Warning: VM detected!")
            status_var.set("VM Detected")
        root.bind("<<InjectionSuccess>>", lambda e: self.updstatus(status_var, log_text, True))
        root.bind("<<InjectionFailed>>", lambda e: self.updstatus(status_var, log_text, False))
        proc_list.bind("<<ListboxSelect>>", lambda e: self.updateproc(proc_list, proc_var))
        root.mainloop()

    def autoproclist(self, proc_list):
        proc_list.delete(0, tk.END)
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                item_text = f"{proc.info['name']} (PID: {proc.info['pid']})"
                proc_list.insert(tk.END, item_text)
                proc_list.itemconfig(tk.END, {'fg': "#FFFFFF"})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def filterer(self, event, proc_list):
        filter_text = event.widget.get().lower()
        proc_list.delete(0, tk.END)
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                item_text = f"{proc.info['name']} (PID: {proc.info['pid']})"
                if filter_text in item_text.lower():
                    proc_list.insert(tk.END, item_text)
                    proc_list.itemconfig(tk.END, {'fg': "#FFFFFF"})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def dllbrowse(self, path_var, dll_text):
        file_path = filedialog.askopenfilename(filetypes=[("DLL files", "*.dll")])
        if file_path:
            path_var.set(file_path)
            dll_text.delete(0, tk.END)
            dll_text.insert(0, f"Selected DLL: {file_path}")

    def openproc(self, proc_var, proc_list):
        proc_win = tk.Toplevel(root)
        proc_win.title("Select Process or Window")
        proc_win.geometry("400x300+250+250")
        proc_win.configure(bg="#2E2E2E")

        view_var = tk.StringVar(value="process")
        tk.Radiobutton(proc_win, text="Process List", variable=view_var, value="process", bg="#2E2E2E", fg="#FFFFFF", command=lambda: self.updatelist(proc_win, view_var.get())).grid(row=0, column=0, padx=5, pady=5)
        tk.Radiobutton(proc_win, text="Window List", variable=view_var, value="window", bg="#2E2E2E", fg="#FFFFFF", command=lambda: self.updatelist(proc_win, view_var.get())).grid(row=0, column=1, padx=5, pady=5)

        list_box = tk.Listbox(proc_win, width=50, height=12, bg="#333333", fg="#FFFFFF")
        list_box.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        self.updatelist(proc_win, view_var.get(), list_box)

        ttk.Button(proc_win, text="Select", command=lambda: self.selected(proc_var, list_box, proc_win)).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(proc_win, text="Exit", command=proc_win.destroy).grid(row=2, column=1, padx=5, pady=5)

    def updatelist(self, win, view_type, list_box=None):
        if list_box is None:
            list_box = win.children["!listbox"]
        list_box.delete(0, tk.END)
        if view_type == "process":
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    item_text = f"{proc.info['name']} (PID: {proc.info['pid']})"
                    list_box.insert(tk.END, item_text)
                    list_box.itemconfig(tk.END, {'fg': "#FFFFFF"})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        else:  # window
            def enum_windows(hwnd, list_box):
                if win32gui.IsWindowVisible(hwnd):
                    title = win32gui.GetWindowText(hwnd)
                    if title:
                        list_box.insert(tk.END, f"{title} (HWND: {hwnd})")
                        list_box.itemconfig(tk.END, {'fg': "#FFFFFF"})
            win32gui.EnumWindows(lambda hwnd, lb=list_box: enum_windows(hwnd, lb), list_box)

    def selected(self, proc_var, list_box, win):
        sel = list_box.curselection()
        if sel:
            item_text = list_box.get(sel[0])
            proc_var.set(item_text)
            win.destroy()

    def log(self, log_text, msg):
        log_text.config(state="normal")
        log_text.insert(tk.END, f"\n[{time.strftime('%H:%M:%S')}] {msg}")
        log_text.see(tk.END)
        log_text.config(state="disabled")

    def layerobf(self, path, key):
        encoded = base64.b64encode(zlib.compress(path.encode())).decode()
        return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(encoded, hashlib.sha256(key).hexdigest()[:len(encoded)]))

    def layerobf_data(self, data, key):
        encoded = base64.b64encode(zlib.compress(data))
        return bytes(a ^ b for a, b in zip(encoded, hashlib.sha256(key).digest() * (len(encoded) // 32 + 1)))

    def vmenvdetector(self):
        vm_indicators = ["VMware" in platform.uname().release, "Virtual" in platform.uname().release, "QEMU" in platform.uname().release, socket.gethostname().lower() in ["virtual", "vmware", "qemu"], "vbox" in platform.uname().release.lower()]
        return any(vm_indicators)

    def getpid(self, proc_list):
        pids = []
        for index in proc_list.curselection():
            item_text = proc_list.get(index)
            pid = int(item_text.split("PID: ")[1].split(")")[0])
            pids.append(pid)
        return pids

    def inject(self, method_var, path_var, proc_list, log_text, status_var, proc_var):
        pids = self.getpid(proc_list)
        if not pids:
            self.log(log_text, "Error: No procs selected!")
            return
        dll_path = path_var.get()
        if not os.path.exists(dll_path):
            self.log(log_text, "Error: DLL file not found!")
            return
        if self.vmenvdetector():
            self.log(log_text, "Aborting: VM detected!")
            return
        status_var.set("Injecting...")
        self.log(log_text, f"Starting injection into {len(pids)} procs with {method_var.get()} method")
        for pid in pids:
            thread = InjectionThread(method_var.get(), pid, dll_path, self.key)
            thread.start()

    def updstatus(self, status_var, log_text, success):
        if success:
            status_var.set("Success")
            self.log(log_text, f"Injection succeeded")
        else:
            status_var.set("Failed")
            self.log(log_text, f"Injection failed")

    def updateproc(self, proc_list, proc_var):
        indices = proc_list.curselection()
        if indices:
            item_text = proc_list.get(indices[0])
            proc_var.set(item_text)
        else:
            proc_var.set("No proc selected")

    def adm(self):
        while True:
            if self.vmenvdetector():
                os._exit(0)
            time.sleep(1)

if __name__ == "__main__":
    root = tk.Tk()
    injector = DLLInjector(root)
    threading.Thread(target=injector.adm, daemon=True).start()

    kernel32 = ctypes.windll.kernel32

    for _ in range(800):
        code = "a = a + 1"
        if random.random() > 0.5:
            code += "; b = b + 2"
        if random.random() > 0.7:
            code += "; c = c + 3"
        if random.random() > 0.9:
            code += "; d = d + 4"
        if random.random() > 0.6:
            proc_handle = kernel32.GetCurrentProcess()
            if kernel32.IsDebuggerPresent():
                os._exit(0)
            mem_status = ctypes.create_string_buffer(64)
            kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status))
            if random.random() > 0.8:
                win32api.OutputDebugString("Anti-detection check")
        if random.random() > 0.5:
            key = os.urandom(32)
            data = "dummy".encode()
            encoded = base64.b64encode(zlib.compress(data))
            obfuscated = bytes(a ^ b for a, b in zip(encoded, hashlib.sha256(key).digest() * (len(encoded) // 32 + 1)))
            decoded = zlib.decompress(base64.b64decode(bytes(b ^ k for b, k in zip(obfuscated, hashlib.sha256(key).digest() * (len(obfuscated) // 32 + 1)))))
            if decoded != data:
                os._exit(0)
        if random.random() > 0.7:
            alloc_addr = kernel32.VirtualAlloc(0, 1024, win32con.MEM_COMMIT | win32con.MEM_RESERVE, win32con.PAGE_EXECUTE_READWRITE)
            if alloc_addr:
                kernel32.VirtualFree(alloc_addr, 0, win32con.MEM_RELEASE)
        if random.random() > 0.6:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if "debugger" in proc.info['name'].lower():
                        os._exit(0)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        if random.random() > 0.5:
            time.sleep(random.uniform(0.01, 0.1))
        if random.random() > 0.8:
            continue
