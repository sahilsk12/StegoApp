import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import cv2
from cryptography.fernet import Fernet
import os

# === Encryption Helpers ===
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as f:
        f.write(key)

def load_key():
    return open("secret.key", "rb").read()

def encrypt_message(msg, key):
    cipher = Fernet(key)
    return cipher.encrypt(msg.encode()).decode()

def encrypt_video(input_path, output_path, key):
    cipher = Fernet(key)
    try:
        with open(input_path, "rb") as f:
            data = f.read()
        encrypted_data = cipher.encrypt(data)
        with open(output_path, "wb") as f:
            f.write(encrypted_data)
        return True
    except Exception as e:
        print(f"Encryption error: {e}")
        return False

def decrypt_video(input_path, output_path, key):
    cipher = Fernet(key)
    try:
        with open(input_path, "rb") as f:
            data = f.read()
        decrypted_data = cipher.decrypt(data)
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
        return True
    except Exception as e:
        print(f"Decryption error: {e}")
        return False

# === Steganography Logic ===
def hide_data(image_path, data, save_path):
    image = cv2.imread(image_path)
    if image is None:
        return None

    data += "#####"
    binary_data = ''.join(format(ord(char), '08b') for char in data)
    data_index = 0

    for row in image:
        for pixel in row:
            for i in range(3):  # BGR channels
                if data_index < len(binary_data):
                    pixel[i] = int(bin(pixel[i])[:-1] + binary_data[data_index], 2)
                    data_index += 1
                else:
                    break

    if not save_path.endswith(".png"):
        save_path += ".png"

    cv2.imwrite(save_path, image)
    return save_path if os.path.exists(save_path) else None

# === Main App ===
class StegoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Stego Tool")
        self.geometry("520x700")
        self.resizable(False, False)
        self.configure(bg="#121212")

        if not os.path.exists("secret.key"):
            generate_key()
        self.key = load_key()

        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self.style.configure('TButton', font=('Segoe UI', 12), padding=8, background='#1f1f1f', foreground='white')
        self.style.map('TButton', background=[('active', '#3a86ff')], foreground=[('active', 'white')])
        self.style.configure('TLabel', background="#121212", foreground="white", font=('Segoe UI', 11))
        self.style.configure('Header.TLabel', font=('Segoe UI', 20, 'bold'), foreground="#3a86ff")
        self.style.configure('SubHeader.TLabel', font=('Segoe UI', 14), foreground="#ddd")

        self.container = tk.Frame(self, bg='#121212')
        self.container.place(relx=0.5, rely=0.5, anchor='center', width=480, height=660)

        self.frames = {}
        for F in (StartPage, EncodePage, DecodePage, EncryptVideoPage, DecryptVideoPage):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.place(relwidth=1, relheight=1)

        self.show_frame(StartPage)

    def show_frame(self, page_class):
        frame = self.frames[page_class]
        frame.tkraise()

class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#121212")
        self.controller = controller

        ttk.Label(self, text="🔐 Stego Tool", style='Header.TLabel').pack(pady=(30,10))
        ttk.Label(self, text="Hide & reveal your secrets securely", style='SubHeader.TLabel').pack(pady=(0,30))

        ttk.Button(self, text="🛡️ Encode Secret Message", command=lambda: controller.show_frame(EncodePage)).pack(pady=10, fill='x')
        ttk.Button(self, text="🔍 Decode Hidden Message", command=lambda: controller.show_frame(DecodePage)).pack(pady=10, fill='x')
        ttk.Button(self, text="🎞️ Encrypt Video", command=lambda: controller.show_frame(EncryptVideoPage)).pack(pady=10, fill='x')
        ttk.Button(self, text="🧩 Decrypt Video", command=lambda: controller.show_frame(DecryptVideoPage)).pack(pady=10, fill='x')

        ttk.Label(self, text="💡 Built with Python & 💙", foreground="#777", font=('Segoe UI', 9)).pack(side='bottom', pady=10)

class EncodePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#121212")
        self.controller = controller
        self.image_path = ""
        self.output_path = ""

        ttk.Label(self, text="🛡️ Encode Message", style='Header.TLabel').pack(pady=20)
        ttk.Button(self, text="📂 Select Image", command=self.select_image).pack(pady=8)
        self.lbl_img = ttk.Label(self, text="", font=('Segoe UI', 10))
        self.lbl_img.pack_forget()

        ttk.Label(self, text="Enter secret message:").pack(pady=(20,5))
        self.entry_msg = ttk.Entry(self, font=('Segoe UI', 12))
        self.entry_msg.pack(ipadx=5, ipady=4, fill='x', padx=20)

        ttk.Button(self, text="💾 Select Save Location", command=self.select_output).pack(pady=15)
        self.lbl_save = ttk.Label(self, text="", font=('Segoe UI', 10))
        self.lbl_save.pack_forget()

        ttk.Button(self, text="🔐 Hide Message", command=self.hide_message).pack(pady=25)
        ttk.Button(self, text="🔙 Back", command=lambda: controller.show_frame(StartPage)).pack(pady=10)

    def select_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg")])
        if path:
            self.image_path = path
            self.lbl_img.config(text=os.path.basename(path), foreground="white")
            self.lbl_img.pack(pady=4)

    def select_output(self):
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if path:
            self.output_path = path
            self.lbl_save.config(text=os.path.basename(path), foreground="white")
            self.lbl_save.pack(pady=4)

    def hide_message(self):
        if not self.image_path or not self.output_path:
            messagebox.showerror("Error", "Please select image and save location.")
            return

        message = self.entry_msg.get()
        if not message:
            messagebox.showerror("Error", "Please enter a secret message.")
            return

        encrypted = encrypt_message(message, self.controller.key)
        result = hide_data(self.image_path, encrypted, self.output_path)

        if result:
            messagebox.showinfo("Success", f"Message hidden! Saved as:\n{result}")
        else:
            messagebox.showerror("Error", "Failed to hide message.")

class DecodePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#121212")
        self.controller = controller
        self.image_path = ""

        ttk.Label(self, text="🔍 Decode Message", style='Header.TLabel').pack(pady=20)
        ttk.Button(self, text="📂 Select Image", command=self.select_image).pack(pady=8)
        self.lbl_img = ttk.Label(self, text="No image selected")
        self.lbl_img.pack(pady=4)

        ttk.Button(self, text="🔓 Extract Message", command=self.extract_message).pack(pady=15)
        self.lbl_output = ttk.Label(self, text="", wraplength=400, font=('Segoe UI', 12, 'bold'))
        self.lbl_output.pack(pady=15)

        ttk.Button(self, text="🔙 Back", command=lambda: controller.show_frame(StartPage)).pack(pady=10)

    def select_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg")])
        if path:
            self.image_path = path
            self.lbl_img.config(text=os.path.basename(path))

    def extract_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first.")
            return

        binary_data = ""
        image = cv2.imread(self.image_path)
        if image is None:
            messagebox.showerror("Error", "Could not open image.")
            return

        for row in image:
            for pixel in row:
                for i in range(3):
                    binary_data += bin(pixel[i])[-1]

        all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
        decoded_data = "".join([chr(int(b, 2)) for b in all_bytes])
        message_with_delimiter = decoded_data.split("#####")[0]

        try:
            decrypted = Fernet(self.controller.key).decrypt(message_with_delimiter.encode()).decode()
            self.lbl_output.config(text=f"🔓 Message: {decrypted}", foreground="#4CAF50")
        except Exception:
            self.lbl_output.config(text="❌ Failed to decrypt message.", foreground="#e53935")

class EncryptVideoPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#121212")
        self.controller = controller
        self.video_path = ""

        ttk.Label(self, text="🎞️ Encrypt Video File with Secret Message", style='Header.TLabel').pack(pady=(20, 10))

        ttk.Button(self, text="📂 Select Video", command=self.select_video).pack(pady=10, ipadx=6)
        self.lbl_vid = ttk.Label(self, text="No video selected", font=('Segoe UI', 10), background="#121212", foreground="white")
        self.lbl_vid.pack(pady=4)

        ttk.Label(self, text="Enter secret message to hide:", background="#121212", foreground="white", font=('Segoe UI', 11)).pack(pady=(15,5))
        self.entry_msg = ttk.Entry(self, font=('Segoe UI', 12))
        self.entry_msg.pack(ipadx=4, ipady=4, fill='x', padx=20)

        ttk.Button(self, text="🔒 Encrypt & Save", command=self.encrypt_video).pack(pady=20, ipadx=10)
        ttk.Button(self, text="🔙 Back", command=lambda: controller.show_frame(StartPage)).pack(pady=10)

    def select_video(self):
        path = filedialog.askopenfilename(filetypes=[("Video files", "*.mp4 *.avi *.mov *.mkv")])
        if path:
            self.video_path = path
            self.lbl_vid.config(text=os.path.basename(path), foreground="white")

    def encrypt_video(self):
        if not self.video_path:
            self.lbl_vid.config(text="⚠️ No video selected!", foreground="#e53935")
            return
        else:
            self.lbl_vid.config(foreground="white")

        secret_msg = self.entry_msg.get()
        if not secret_msg:
            messagebox.showerror("Error", "Please enter a secret message to hide.")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted File", "*.enc")])
        if not save_path:
            return

        try:
            key = self.controller.key
            cipher = Fernet(key)

            with open(self.video_path, "rb") as f:
                video_data = f.read()

            # Encode message and video data together:
            # 1. Encrypt message separately
            encrypted_msg = cipher.encrypt(secret_msg.encode())

            # 2. Combine: store length of encrypted message (4 bytes) + encrypted message + video data
            msg_len = len(encrypted_msg).to_bytes(4, byteorder='big')
            combined_data = msg_len + encrypted_msg + video_data

            # 3. Encrypt the combined data again
            final_encrypted = cipher.encrypt(combined_data)

            with open(save_path, "wb") as f:
                f.write(final_encrypted)

            messagebox.showinfo("Success", f"Video and message encrypted and saved as:\n{save_path}")
            # Clear message field after success
            self.entry_msg.delete(0, 'end')
            self.lbl_vid.config(text="No video selected", foreground="white")
            self.video_path = ""

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")



class DecryptVideoPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#121212")
        self.controller = controller
        self.encrypted_path = ""
        self.output_path = ""

        ttk.Label(self, text="🧩 Decrypt Video and Extract Message", style='Header.TLabel').pack(pady=20)
        ttk.Button(self, text="📂 Select Encrypted File", command=self.select_encrypted).pack(pady=10)
        self.lbl_enc = ttk.Label(self, text="No file selected", background="#121212", foreground="white")
        self.lbl_enc.pack(pady=4)

        ttk.Button(self, text="💾 Select Save Location (video)", command=self.select_output).pack(pady=10)
        self.lbl_save = ttk.Label(self, text="", background="#121212", foreground="white")
        self.lbl_save.pack(pady=4)

        self.lbl_msg = ttk.Label(self, text="", wraplength=400, font=('Segoe UI', 12, 'bold'), background="#121212")
        self.lbl_msg.pack(pady=15)

        ttk.Button(self, text="🔓 Decrypt and Extract", command=self.decrypt_and_extract).pack(pady=20)
        ttk.Button(self, text="🔙 Back", command=lambda: controller.show_frame(StartPage)).pack(pady=10)

    def select_encrypted(self):
        path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if path:
            self.encrypted_path = path
            self.lbl_enc.config(text=os.path.basename(path), foreground="white")

    def select_output(self):
        path = filedialog.asksaveasfilename(defaultextension=".mp4", filetypes=[("Video Files", "*.mp4 *.avi *.mov")])
        if path:
            self.output_path = path
            self.lbl_save.config(text=os.path.basename(path), foreground="white")

    def decrypt_and_extract(self):
        if not self.encrypted_path or not self.output_path:
            messagebox.showerror("Error", "Please select both the encrypted file and output save location.")
            return

        try:
            key = self.controller.key
            cipher = Fernet(key)

            with open(self.encrypted_path, "rb") as f:
                encrypted_blob = f.read()

            # Step 1: Decrypt the entire blob
            decrypted_blob = cipher.decrypt(encrypted_blob)

            # Step 2: Read first 4 bytes to get length of encrypted message
            msg_len = int.from_bytes(decrypted_blob[:4], byteorder='big')

            # Step 3: Extract encrypted message and decrypt it
            encrypted_msg = decrypted_blob[4:4+msg_len]
            decrypted_msg = cipher.decrypt(encrypted_msg).decode()

            # Step 4: The rest is the video data
            video_data = decrypted_blob[4+msg_len:]

            # Step 5: Save video data
            with open(self.output_path, "wb") as f:
                f.write(video_data)

            self.lbl_msg.config(text=f"🔓 Hidden Message: {decrypted_msg}", foreground="#4CAF50")
            messagebox.showinfo("Success", f"Video decrypted and message extracted!\nSaved video to:\n{self.output_path}")

        except Exception as e:
            self.lbl_msg.config(text="❌ Failed to decrypt or extract message.", foreground="#e53935")
            messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")


if __name__ == "__main__":
    app = StegoApp()
    app.mainloop()
