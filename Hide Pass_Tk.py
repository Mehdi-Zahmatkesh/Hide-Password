import tkinter
import tkinter.messagebox
import os
import datetime
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#cryptography
password_provided = "password"  # This is input in the form of a string
password = password_provided.encode()  # Convert to type bytes
salt = b'salt_'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once

from cryptography.fernet import Fernet

#time now
now = datetime.datetime.now().strftime('%c')

#first tkinter
root = tkinter.Tk()
root.title('Login Program')
root.geometry('400x400')
root.iconbitmap('victor.ico')

#defualt user and pass
mainUser = 'admin'
mainPassword = 'admin'

labelFrame = tkinter.LabelFrame(root,text='Login',bd=5)
labelFrame.pack(fill='both',expand='yes')

firstLabel = tkinter.Label(root,text='UserName :')
firstLabel.place(x=10,y=20)

secondLabel = tkinter.Label(root,text='Password :')
secondLabel.place(x=15,y=45)

firstEntey = tkinter.Entry(root)
firstEntey.place(x=80,y=22)

secondEntry = tkinter.Entry(root,show='*')
secondEntry.place(x=80,y=47)

#change checkbutton
def showpassword():
    if dataBoxF.get() == 1:
        secondEntry.config(show='')
    else:
        secondEntry.config(show='*')    

dataBoxF = tkinter.IntVar()        
showPass = tkinter.Checkbutton(root,text='Show Password',command=showpassword,variable=dataBoxF)
showPass.place(x=230,y=47)


def incorrectPass():
    user = firstEntey.get()
    passW = secondEntry.get()
    if user != mainPassword or passW != mainPassword :
        tkinter.messagebox.showerror('Error','Username or Password is incorrect ❌')
    else:
        #second tkinter
        root.destroy()
        main = tkinter.Tk()
        main.title('Hide Password')
        main.geometry('500x500')

        labelFrame = tkinter.LabelFrame(main,text='Save or Decrypt Pass ',bd=5)
        labelFrame.pack(fill='both',expand='yes')

        mainFirstLabel = tkinter.Label(main,text='Password :')
        mainFirstLabel.place(x=20,y=20)

        mainSecLabel = tkinter.Label(main,text='Description :')
        mainSecLabel.place(x=10,y=45)

        mainFirstEntry = tkinter.Entry(main,show='*')
        mainFirstEntry.place(x=85,y=22)

        def showmainpassword():
            if dataBoxS.get() == 1:
                mainFirstEntry.config(show='')
            else:
                mainFirstEntry.config(show='*')
            
        dataBoxS = tkinter.IntVar()
        showMainPass = tkinter.Checkbutton(main,text='Show Password',command=showmainpassword,variable=dataBoxS)
        showMainPass.place(x=250,y=18)

        mainSecEntry = tkinter.Entry(main,width=50)
        mainSecEntry.place(x=85,y=47)

        #save pass and user in file
        def passfile():
            mainGet = mainFirstEntry.get()
            mainGetB = mainGet.encode()
            f = Fernet(key)
            FE = f.encrypt(mainGetB)
            SE = mainSecEntry.get()
            filePass = open('C:/Hide Password/information.txt','a+')
            filePass.write(f'\nData : {now}\nPassword : {FE}\nDescription : {SE}\n') 
            filePass.close()
        

        mainButton = tkinter.Button(main,text='import',width=15,command=passfile)
        mainButton.place(x=170,y=80)

        unlockLabel = tkinter.Label(main,text='Decrypt Password :')
        unlockLabel.place(x=10,y=120)

        unlockEntry = tkinter.Entry(main,width=50)
        unlockEntry.place(x=120,y=120)

        infoLabel = tkinter.Label(main,text='Go address: C:/Hide Password/information.txt(Enter Without b)',fg='red')
        infoLabel.place(x=100,y=145)

        #decrypt pass
        def unlockpass():
            codeCopy = unlockEntry.get()
            codeCopyB = codeCopy.encode()
            f = Fernet(key)
            decrypt = f.decrypt(codeCopyB)
            labelShow = tkinter.Label(main,text=decrypt,fg='red')
            labelShow.place(x=80,y=220)


        unlockShow = tkinter.Label(main,text='Password is ')
        unlockShow.place(x=10,y=220)

        unlockButton = tkinter.Button(main,text='Decrypt',width=15,command=unlockpass)
        unlockButton.place(x=170,y=190)

        main.mainloop

firstButton = tkinter.Button(root,text='Login 🔒',width=15,command=incorrectPass)
firstButton.place(x=150,y=100)

root.mainloop()


#created by O7_VICTOR_8O
#Telegram ID : V7_VICTOR_8V
#Instagram ID : O7VICTOR8O