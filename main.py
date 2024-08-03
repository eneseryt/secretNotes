import tkinter as tk
from PIL import ImageTk,Image
import os
from base64 import b64encode, b64decode
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

FONT = ("Arial", 12,"bold ")

#Encryption Part
def generate_key(password):
    # Sabit bir salt kullanın
    salt = b'some_salt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def save_encrypted_file():
    file_name = title_entry.get()
    content = secret_text.get("1.0", tk.END).strip()
    key = key_entry.get()

    if file_name and content and key:
        try:
            fernet = Fernet(generate_key(key))
            encrypted_content = fernet.encrypt(content.encode()).decode('utf-8')
            with open(f"{file_name}.txt", "w") as file:
                file.write(f"{file_name}\n{encrypted_content}")
            # Başlık, içerik ve anahtar alanlarını temizle
            title_entry.delete(0, tk.END)
            secret_text.delete("1.0", tk.END)
            key_entry.delete(0, tk.END)
            messagebox.showinfo("Başarılı", f"{file_name}.txt oluşturuldu ve şifrelendi.")
        except Exception as e:
            messagebox.showerror("Hata", str(e))
    else:
        messagebox.showerror("Hata", "Lütfen başlık, içerik ve anahtar girin.")

#Decryption Part
def decrypt_file():
    encrypted_content = title_entry.get()
    key = key_entry.get()

    if encrypted_content and key:
        try:
            fernet = Fernet(generate_key(key))
            decrypted_content = fernet.decrypt(encrypted_content.encode()).decode()
            secret_text.delete("1.0", tk.END)
            secret_text.insert(tk.END, decrypted_content)
        except Exception as e:
            messagebox.showerror("Hata", str(e))
    else:
        messagebox.showerror("Hata", "Lütfen şifrelenmiş öğe ve anahtar girin.")



window=tk.Tk()
window.title("Secret Notes")
window.geometry("600x900")
#window.config(bg="white")

#window.configure(bg="light blue")

#FUNCTIONS



#Photo

image_path = "C:\\Users\\enese\\Downloads\\top_secret.png"
image = Image.open(image_path)
new_size = (250,200)
resized_image = image.resize(new_size)
photo = ImageTk.PhotoImage(resized_image)

label = tk.Label(image=photo)
label.image = photo
label.place(x=175, y=20)  #Thanks to .place method we can set our argumans in coordinat system


#Label Part For Title
title_label = tk.Label(text="Enter your title", font=FONT)
title_label.place(x=238, y=230)

#Entry Part For Title

title_entry = tk.Entry(width=50)
title_entry.focus()
title_entry.place(x=147, y=255)

#Secret Label
title_entry2=tk.Label()
title_entry2.pack()
#Second Label Part For Secret Text

label2 = tk.Label(text="Enter your secret", font=FONT)
label2.place(x=230, y=280)

#Text Part

secret_text = tk.Text(width=56,height=26)
secret_text.config(bg="green")
secret_text.place(x=67, y=310)

#Third Label Part For Master Key

label3 = tk.Label(text="Enter master key", font=FONT)
label3.place(x=220, y=733)

#Entry For Master Key

key_entry = tk.Entry(width=50)
key_entry.place(x=147, y=758)

#Save And Encrypt Button
button1 = tk.Button(text="Save & Encrypt", command=save_encrypted_file)
button1.place(x=240, y=786)

#Decrypt Button
button2 = tk.Button(text="Decrypt", command=decrypt_file)
button2.place(x=258, y=815)



#Status Label
status_label = tk.Label(text="")
status_label.place(x=250, y=840)

#Encrypted Label Part
encrypted_label=tk.Label()
encrypted_label.pack()

#Decrypted Label
decrypted_label=tk.Label()
decrypted_label.pack()



window.mainloop()








