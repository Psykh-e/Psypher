import os
import random
import colorama
from time import sleep
import pyfiglet
import sys
from rich.console import Console
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

console = Console()
KEYFILE = "psykhe.key"
ALLOWED_FILES = [".txt",".png",".jpg",".jpeg",".gif",".doc",".docx",".mp4",".mp3",".pdf",".odt",".xls",".xlsx",".json",".php",".exe",".sql",".csv",".xml"]
RUN = True
colorama.init(autoreset=True)


#ENCRYPT CFG
def enc_cfg(text):
    encrypted_cfg_text = ""
    key = []
    for char in text:
        rand_val = random.randint(1, 256)
        key.append(str(rand_val))
        encrypted_cfg_text += chr((ord(char) + rand_val) % 256)

    with open("config.cfg", "w", encoding="utf-8") as file:
        file.write(",".join(key) + "\n")
        file.write(encrypted_cfg_text)

#DECRYPT CFG
def dec_cfg():
    with open("config.cfg", "r", encoding="utf-8") as file:
        key_line = file.readline()
        key = [int(x) for x in key_line.strip().split(",")]
        encrypted_cfg_text = file.read()

    decrypted_cfg_text = ""
    for i, char in enumerate(encrypted_cfg_text):
        decrypted_cfg_text += chr((ord(char) - key[i]) % 256)

    return decrypted_cfg_text


#ENCRYPT
def encrypt(filename):
	if(os.path.exists(filename)):
		file = open(filename,"rb+")
		data = file.read()
		file.seek(0)

		if(len(data) > 0):
			name,extension = os.path.splitext(filename)
			new_name = filename+"_psykhenc"
			i = 0
			while os.path.exists(new_name) == True :
				i += 1
				new_name = name+"_"+str(i)+extension+"_psykhenc"

			fernet = Fernet(key)
			try :
				encrypted = fernet.encrypt(data)
			except TypeError:
				print(colorama.Back.LIGHTRED_EX+ colorama.Fore.BLACK+"FAILED"+colorama.Style.RESET_ALL+" '"+ colorama.Fore.CYAN+ filename + colorama.Style.RESET_ALL+"' could not encrypted because the data is not binary")
				file.close()
			else :
				change = file.write(encrypted)
				file.close()
				os.rename(filename,new_name)
			
			print(colorama.Back.LIGHTGREEN_EX+ colorama.Fore.BLACK+"SUCCESS"+colorama.Style.RESET_ALL+" '"+ colorama.Fore.CYAN+ filename + colorama.Style.RESET_ALL+"' has encrypted and renamed as '"+ colorama.Fore.CYAN+ new_name + colorama.Style.RESET_ALL+"'")
		else :
			print(colorama.Back.LIGHTRED_EX+ colorama.Fore.BLACK+"WARNING"+colorama.Style.RESET_ALL+" '"+ colorama.Fore.CYAN+ filename + colorama.Style.RESET_ALL+"' could not encrypted because it's empty")
			file.close()

#DECRYPT
def decrypt(filename):
	if(os.path.exists(filename) == True):
		new_name = filename.rsplit("_psykhenc")[0]
		os.rename(filename,new_name)
		file = open(new_name,"rb+")
		data = file.read()
		file.close()
		if(len(data) > 0):
			fernet = Fernet(key)
			try :
				decrypted = fernet.decrypt(data)
			except InvalidToken:
				print(colorama.Back.LIGHTRED_EX+ colorama.Fore.BLACK+"FAILED"+colorama.Style.RESET_ALL+" '"+ colorama.Fore.CYAN+ filename + colorama.Style.RESET_ALL+"' could not decrypted because key invalid")
				os.rename(new_name,filename)
			except TypeError:
				print(colorama.Back.LIGHTRED_EX+ colorama.Fore.BLACK+"FAILED"+colorama.Style.RESET_ALL+" '"+ colorama.Fore.CYAN+ filename + colorama.Style.RESET_ALL+"' could not decrypted because the data is not binary")
				os.rename(new_name,filename)
			else :
				file = open(new_name,"wb")
				change = file.write(decrypted)
				file.close()
				print(colorama.Back.LIGHTGREEN_EX+ colorama.Fore.BLACK+"SUCCESS"+colorama.Style.RESET_ALL+" '"+ colorama.Fore.CYAN+ filename + colorama.Style.RESET_ALL+"' has decrypted and renamed as '"+ colorama.Fore.CYAN+ new_name + colorama.Style.RESET_ALL+"'")

		else :
			print(colorama.Back.LIGHTRED_EX+ colorama.Fore.BLACK+"WARNING"+colorama.Style.RESET_ALL+" '"+ colorama.Fore.CYAN+ filename + colorama.Style.RESET_ALL+"' could not decrypted because it's empty")





message1 = "Welcome to Psypher\n\
Program does not promise warranty!\n\
Everything is the responsibility of the user!\n\
No responsibility is accepted for misuse or errors that may occur during operation!\n\
Use it at your own risk!\n\
(Default password: test)\n"

#TYPEWRITER
def typewriter(message):
    for char in message:
        sys.stdout.write(char)
        sys.stdout.flush()
        
        if char != "\n":
            sleep(0.04)
        else:
            sleep(0.25)

os.system("cls")



content = dec_cfg()
paths = content.split("\n")
passwd_f = paths[0]
mode_f = paths[1]





if (mode_f == "0"):
    typewriter(message1)
    with console.status("[bold green]System Starting, Please Wait..."):
        sleep(3.5)
    os.system("cls")
    sec_question = int(input(str(colorama.Fore.RED) + "In case of forgetting your password, you must choose a security question.\n\n"
                         + str(colorama.Fore.GREEN) + "1. What is the name of your primary school?\n"
                         + str(colorama.Fore.GREEN) + "2. What was the name of your first pet?\n"
                         + str(colorama.Fore.GREEN) + "3. What is your favorite sport?\n"
                         + str(colorama.Fore.GREEN) + "4. What city were you born in?\n"
                         + str(colorama.Fore.GREEN) + "5. What was the make/model of your first car?\n\n"
                         + str(colorama.Fore.CYAN) + "Please Select a Security Question: "+ colorama.Style.RESET_ALL))
    if sec_question not in list(range(1, 6)):
        with console.status("[bold red]Wrong choice! Program shutting down...",spinner="dots2"):
                sleep(2)
                os.system("cls")
                exit()

    sec_answer = input("Answer: ").lower()
    if sec_answer == "":
        with console.status("[bold red]Security answer cannot be null! Program shutting down...",spinner="dots2"):
            sleep(2)
            os.system("cls")
            exit()
         
    mode_f = "1"
    os.system("cls")
else:
    pass


if len(paths) > 2:
    sec_question_f = paths[2]
else:
    sec_question_f = str(sec_question)


if len(paths) > 3:
    sec_answer_f = paths[3]
else:
    sec_answer_f = sec_answer

strings = [passwd_f, mode_f, sec_question_f, sec_answer_f]
cfg = ""
for string in strings:
    cfg += string + "\n"
enc_cfg(cfg)

 


font_list = ["3-d", "5lineoblique", "alphabet", "avatar", "banner", "banner3", "basic", "bell", "big", "block", "bubble", "bulbhead", "catwalk", "chunky", 
              "coinstak", "colossal", "computer", "contessa", "cosmic", "cricket", "cyberlarge", "cybermedium", "digital", "doom", "eftipiti", "eftiwater",
              "fourtops", "fuzzy", "gothic", "graffiti", "invita", "italic", "jazmine", "kban", "larry3d", "linux", "madrid", "nancyj-fancy", "rectangles",
              "smkeyboard", "speed", "stop"]
print(pyfiglet.figlet_format("Welcome " + os.environ["USERNAME"], font= random.choice(font_list) ))
print("https://github.com/Psykh-e")
print("https://twitter.com/Psykh_e")
print("https://www.instagram.com/psykhe.sh/")
print()
while(True):

    i = input("Encrypt/Decrypt (E/D): ")
    

    if (i == "E" or i == "e"):
        os.system("cls")

        if os.path.exists(KEYFILE) == False:
            file = open(KEYFILE, "wb")
            key = Fernet.generate_key()
            file.write(key)
            print("\n\nEncryption Key File Not Found!")
            with console.status("[bold green]The new one is creating..."):
                sleep(1)
        else:
            file = open(KEYFILE, "rb")
            key = file.read()
            print("\n\nEncryption Key File found on the system.")
        file.close()
        with console.status("[bold green]Generating Encryption Key..."):
                sleep(1)
                   
        print(colorama.Fore.YELLOW+"\nEncryption Key: " + str(key))

        for root, dirs, files in os.walk(".") :
            for filename in files:
                filesize = os.stat(filename).st_size
                parts = filename.split(".")
                extension = "." + parts[1]
                name = parts[0]
                extension = extension.lower()
                if(extension in ALLOWED_FILES):
                    with console.status(f"[bold green]Encrypting {filename}..."):
                        encrypt(filename)
        
        print(colorama.Fore.GREEN+"\n\nEncryption Completed!\n\n")
        break



    if (i == "D" or i == "d"):
        os.system("cls")

        print("Change your password? / Forgot your password? ('Press Enter')")
        passwd = input("Please enter password : ")
        if(passwd == passwd_f):

            if os.path.exists(KEYFILE) == False :
                with console.status("[bold green]Encryption Key Searching..."):
                    sleep(1)
                print(colorama.Back.YELLOW+"\n\nEncryption Key is not found! System will not work!")
                RUN = False
                break
            else:
                file = open(KEYFILE, "rb")
                key = file.read()
                with console.status("[bold green]Encryption Key Searching..."):
                    sleep(1)
                print("\n\nEncryption Key File found on the system.")
                file.close()
            if(RUN):
                print(colorama.Fore.YELLOW+"\nEncryption Key: " + str(key))

                for root, dirs, files in os.walk(".") :
                    for filename in files:
                        parts = filename.split("_")
                        if(parts[-1] == "psykhenc"):
                            with console.status(f"[bold green]Decrypting {filename}..."):
                                decrypt(filename)
                            
                print(colorama.Fore.GREEN+"\n\nDecryption Completed!\n\n")	
                break
        
        elif (passwd == ""):
            content = dec_cfg()
            paths = content.split("\n")
            passwd_f = paths[0]
            mode_f = paths[1]
            sec_question_f = paths[2]
            sec_answer_f = paths[3]


            if sec_question_f == "1":
                sec_answer = input("\nWhat is the name of your primary school? ").lower()
                if sec_answer_f == sec_answer:
                    new_passwd = input("Please Enter Your New Password: ")
                    if new_passwd == "":
                        with console.status("[bold red]Password cannot be null! Program shutting down...",spinner="dots2"):
                            sleep(2)
                            os.system("cls")
                            exit()
                    passwd_f = new_passwd
                    strings = [passwd_f, mode_f, sec_question_f, sec_answer_f]
                    cfg = ""
                    for string in strings:
                        cfg += string + "\n"
                    enc_cfg(cfg)
                    with console.status("[bold green]Password changed successfully, Program shutting down..."):
                        sleep(3.5)
                        os.system("cls")
                        exit()
                else:
                    with console.status("[bold red]The answer to the security question is wrong! Program shutting down...",spinner="dots2"):
                        sleep(2)
                        os.system("cls")
                        exit()
            

            
            elif sec_question_f == "2":
                sec_answer = input("\nWhat was the name of your first pet? ").lower()
                if sec_answer_f == sec_answer:
                    new_passwd = input("Please Enter Your New Password: ")
                    if new_passwd == "":
                        with console.status("[bold red]Password cannot be null! Program shutting down...",spinner="dots2"):
                            sleep(2)
                            os.system("cls")
                            exit()
                    passwd_f = new_passwd
                    strings = [passwd_f, mode_f, sec_question_f, sec_answer_f]
                    cfg = ""
                    for string in strings:
                        cfg += string + "\n"
                    enc_cfg(cfg)
                    with console.status("[bold green]Password changed successfully, Program shutting down..."):
                        sleep(3.5)
                        os.system("cls")
                        exit()
                else:
                    with console.status("[bold red]The answer to the security question is wrong! Program shutting down...",spinner="dots2"):
                        sleep(2)
                        os.system("cls")
                        exit()
            
            

            elif sec_question_f == "3":
                sec_answer = input("\nWhat is your favorite sport? ").lower()
                if sec_answer_f == sec_answer:
                    new_passwd = input("Please Enter Your New Password: ")
                    if new_passwd == "":
                        with console.status("[bold red]Password cannot be null! Program shutting down...",spinner="dots2"):
                            sleep(2)
                            os.system("cls")
                            exit()
                    passwd_f = new_passwd
                    strings = [passwd_f, mode_f, sec_question_f, sec_answer_f]
                    cfg = ""
                    for string in strings:
                        cfg += string + "\n"
                    enc_cfg(cfg)
                    with console.status("[bold green]Password changed successfully, Program shutting down..."):
                        sleep(3.5)
                        os.system("cls")
                        exit()
                else:
                    with console.status("[bold red]The answer to the security question is wrong! Program shutting down...",spinner="dots2"):
                        sleep(2)
                        os.system("cls")
                        exit()
            

            
            elif sec_question_f == "4":
                sec_answer = input("\nWhat city were you born in? ").lower()
                if sec_answer_f == sec_answer:
                    new_passwd = input("Please Enter Your New Password: ")
                    if new_passwd == "":
                        with console.status("[bold red]Password cannot be null! Program shutting down...",spinner="dots2"):
                            sleep(2)
                            os.system("cls")
                            exit()
                    passwd_f = new_passwd
                    strings = [passwd_f, mode_f, sec_question_f, sec_answer_f]
                    cfg = ""
                    for string in strings:
                        cfg += string + "\n"
                    enc_cfg(cfg)
                    with console.status("[bold green]Password changed successfully, Program shutting down..."):
                        sleep(3.5)
                        os.system("cls")
                        exit()
                else:
                    with console.status("[bold red]The answer to the security question is wrong! Program shutting down...",spinner="dots2"):
                        sleep(2)
                        os.system("cls")
                        exit()
            
            

            elif sec_question_f == "5":
                sec_answer = input("\nWhat was the make/model of your first car?").lower()
                if sec_answer_f == sec_answer:
                    new_passwd = input("Please Enter Your New Password: ")
                    if new_passwd == "":
                        with console.status("[bold red]Password cannot be null! Program shutting down...",spinner="dots2"):
                            sleep(2)
                            os.system("cls")
                            exit()
                    passwd_f = new_passwd
                    strings = [passwd_f, mode_f, sec_question_f, sec_answer_f]
                    cfg = ""
                    for string in strings:
                        cfg += string + "\n"
                    enc_cfg(cfg)
                    with console.status("[bold green]Password changed successfully, Program shutting down..."):
                        sleep(3.5)
                        os.system("cls")
                        exit()
                else:
                    with console.status("[bold red]The answer to the security question is wrong! Program shutting down...",spinner="dots2"):
                        sleep(2)
                        os.system("cls")
                        exit()


    

        else:
            with console.status("[bold red]Incorrect password! Program shutting down...",spinner="dots2"):
                sleep(2)
            os.system("cls")
            break

    else:
        print("\nInvalid selection! Please try again!\n\n")
