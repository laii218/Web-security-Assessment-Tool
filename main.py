from tkinter import *
from PIL import ImageTk, Image
from ScrapingTool import scraping
from vulnerability_scanner import vulnerability_scanner
from ParamSpiderTool import param_spider_tool
from Password_Operations import password_operations
import customtkinter

# create the main window
root = customtkinter.CTk()
# set the appearance mode
customtkinter.set_appearance_mode("dark")
# set the default color theme
customtkinter.set_default_color_theme("dark-blue")
# set the title of the window
root.title("Web Security Assessment Tool")
# set the window size
root.geometry("1000x500")
# set the window to be not resizable
root.resizable(True, True)
# design the Main Window
root.configure(fg_color="#1e88e5")


# Open the image file
img = Image.open("background1.jpg")

# Resize the image to fit the window size
img = img.resize((root.winfo_screenwidth(), root.winfo_screenheight()), Image.BICUBIC)

# Create a PhotoImage object from the resized image
bg_img = ImageTk.PhotoImage(img)

# Create a Label widget with the image as background
bg_label = customtkinter.CTkLabel(root, image=bg_img)
bg_label.place(x=0, y=0, relwidth=1, relheight=1)

# the main label of the window this has the overall information about the tool
about_the_tool=customtkinter.CTkLabel(root, text="Security Tool for web usage that contains multiple features for collecting data from websites,\n the features are :\n"
                                "\n 1-) Web Scraping : also known as data scraping, is the process of automatically extracting data from websites.\n"
                                "\n 2-) Parameter Spider : is a web parameters hunter , it searches for the parameters in the url .\n"
                                "\n 3-) Vulnerability Scanner : is the process of using Random payloads into websites and check their response if a potential vulnerability exists or not  \n"
                                "\n 4-) Password Operation: is  a Tool that helps with Password operations such as (password generator and hash cracker)\n"
                                "\n you can find more information from the buttons above.\n"
                                "\n remember to use this tool legally and in an ethical way. ")
# place the label in the center of the window
about_the_tool.configure(font=("Courier", 14), fg_color="#0B1320")
about_the_tool.pack(fill="both", expand=True)
about_the_tool.place(relx=0.5, rely=0.5, anchor=CENTER)

# password operation button and the background image of it is placed
background1 = Image.open("dark.png")
background1 = background1.resize((15, 15), Image.BICUBIC)
img_tk4 = customtkinter.CTkImage(background1)

Password_Operation_Button = customtkinter.CTkButton(master=root, text="Password Operations",image=img_tk4, compound='left', command=password_operations, width=20, height=2)

# scraping button and the background image of it is placed
background2 = Image.open("dark.png")
background2 = background2.resize((15, 15), Image.BICUBIC)
img_tk2 = customtkinter.CTkImage(background2)

Scraping_button = customtkinter.CTkButton(master=root, text="Scraping Tool",image=img_tk2,compound='left', command=scraping, width=20, height=2,)

# param spider button and the background image of it is placed
background5 = Image.open("dark.png")
background5 = background5.resize((15, 15), Image.BICUBIC)
img_tk6 = customtkinter.CTkImage(background5)

ParamSpider_button = customtkinter.CTkButton(master=root, text="ParamSpider Tool",image=img_tk6, compound="left",  command=param_spider_tool, width=20, height=2)

# crawling button and the background image of it is placed
background6 = Image.open("dark.png")
background6 = background6.resize((15, 15), Image.BICUBIC)
img_tk7 = customtkinter.CTkImage(background6)

Vulnerability_Scanner_button = customtkinter.CTkButton(master=root, text="Vuln Scanner", image=img_tk7, compound='left', command=vulnerability_scanner, width=20, height=2)


# place the buttons in the window
def about_scraping_tool():
    # create a new window
    scraping_window = customtkinter.CTkToplevel()
    # set the appearance mode
    customtkinter.set_appearance_mode("dark")
    # set the default color theme
    customtkinter.set_default_color_theme("dark-blue")
    # set the title of the window
    scraping_window.title("About Web Scraping Tool")
    # set the window size
    scraping_window.geometry("1500x900")
    # open the image file
    background_image_for_about_scraping_tool = Image.open("background1.jpg")
    # resize the image to fit the window size
    background_image_for_about_scraping_tool = background_image_for_about_scraping_tool.resize((scraping_window.winfo_screenwidth(), scraping_window.winfo_screenheight()), Image.BICUBIC)
    # create a PhotoImage object from the resized image
    background_image_for_about_scraping_tool_object = ImageTk.PhotoImage(background_image_for_about_scraping_tool)
    # create a Label widget with the image as background
    background_image_for_about_scraping_tool_label = customtkinter.CTkLabel(scraping_window, image=background_image_for_about_scraping_tool_object)
    # place the label in the center of the window
    background_image_for_about_scraping_tool_label.place(x=0, y=0, relwidth=1, relheight=1)
    # the label that contains the information about the scraping tool
    about_scraping_label = customtkinter.CTkLabel(master=scraping_window, text="Web scraping, also known as data scraping, is the process of automatically extracting data from websites.\n This technique is used to collect large amounts of data \nfrom websites that would otherwise be time-consuming or difficult to extract manually."
    
                                                       "\n Web scraping can be done in various ways,\n including by using programming languages like Python \n or by using specialized tools like web scraping software.\n Here are some examples of web scraping:\n"
                                                       "\n1-) Price comparison websites: Websites like Amazon or eBay\n are popular destinations for online shoppers,\n and web scraping is used to extract data on product prices, ratings, and reviews.\n This information is then used to create price comparison websites like PriceGrabber or Shopzilla.\n"
                                                       "\n2-) Social media analytics: Social media platforms like Twitter or Facebook\n provide a wealth of data that can be used for social media analytics.\n Web scraping is used to extract data on user engagement, sentiment analysis,\n and other metrics that can be used for marketing purposes.\n"
                                                       "\n Overall, web scraping is a powerful tool that can be used for a wide range of applications,\n from business intelligence to scientific research.\n However, it's important to use web scraping ethically and legally,\n respecting the terms of service of the websites you're scraping \n and following all applicable laws and regulations.")
    # place the label in the center of the window
    about_scraping_label.pack(fill="both", expand=True)
    about_scraping_label.place(rely=0.5, relx=0.5, anchor=CENTER)
    about_scraping_label.configure(font=("Courier", 16), fg_color="#0B1320")
    # create a back button
    back_button = customtkinter.CTkButton(master=scraping_window, text="Back", command=scraping_window.destroy)
    back_button.pack()
    back_button.place(relx=0.5, rely=0.9, anchor=CENTER)
    back_button.configure(font=("Courier", 16), fg_color="#0B1320")


# place the background image of the button
image1 = Image.open("owasp.jpg")
image1 = image1.resize((15, 15), Image.BICUBIC)
img_tk1 = customtkinter.CTkImage(image1)

about_scraping = customtkinter.CTkButton(master=root, text="about Scraping Tool", image=img_tk1, compound='left', command=about_scraping_tool, width=50, height=10)
about_scraping.pack()
about_scraping.place(relx=0.39, rely=0.1, anchor=CENTER)
about_scraping.configure(font=("Courier", 14), fg_color="#0B1320")


# place the buttons in the window
def about_params_spider():
    # create a new window
    param_window = customtkinter.CTkToplevel()
    # set the appearance mode
    customtkinter.set_appearance_mode("dark")
    # set the default color theme
    customtkinter.set_default_color_theme("dark-blue")
    # set the title of the window
    param_window.title("About ParamSpider Tool")
    # set the window size
    param_window.geometry("1500x900")
    # open the image file
    background_image_for_about_paramspider_tool = Image.open("background1.jpg")
    # resize the image to fit the window size
    background_image_for_about_paramspider_tool = background_image_for_about_paramspider_tool.resize((param_window.winfo_screenwidth(), param_window.winfo_screenheight()), Image.BICUBIC)
    # create a PhotoImage object from the resized image
    background_image_for_about_paramspider_tool_object = ImageTk.PhotoImage(background_image_for_about_paramspider_tool)
    # create a Label widget with the image as background
    background_image_for_about_paramspider_tool_label = customtkinter.CTkLabel(param_window, image=background_image_for_about_paramspider_tool_object)
    # place the label in the center of the window
    background_image_for_about_paramspider_tool_label.place(x=0, y=0, relwidth=1, relheight=1)
    # the label that contains the information about the paramspider tool
    about_param_spider_tool = customtkinter.CTkLabel(param_window, text="Parameter Spider is a web application scanner tool that helps in identifying vulnerabilities and security issues in web applications.\n It works by scanning a website for various parameters and then testing them for vulnerabilities."
                                                       "\n Here are some examples of how Parameter Spider tool works:\n"
                                                       "\n 1-) SQL Injection: Parameter Spider tool can identify SQL injection vulnerabilities in a web application\n by sending malicious SQL queries through input fields or parameter\n If the application is vulnerable, it will return sensitive information, such as usernames and passwords.\n"
                                                       "\n 2-) Cross-site scripting (XSS):Parameter Spider tool can identify cross-site scripting vulnerabilities in a web application\n by injecting malicious scripts through input fields or parameters.\nIf the application is vulnerable,\nit will execute the malicious script and allow the attacker to steal user data or hijack user sessions.\n"
                                                       "\n Overall, Parameter Spider tool is a powerful tool for identifying vulnerabilities in web applications.\n However, it's important to use it ethically and legally,\n respecting the terms of service of the websites you're scanning\n and following all applicable laws and regulations.\n It's also important to perform thorough testing and validation\n of any vulnerabilities identified by the tool before reporting\n them to the website owner or security team.",pady=5,padx=5)
# place the label in the center of the window
    about_param_spider_tool.pack(fill="both", expand=True)
    about_param_spider_tool.place(relx=0.5, rely=0.5, anchor=CENTER)
    about_param_spider_tool.configure(font=("Courier", 16), fg_color="#0B1320")
    # create a back button
    back_button = customtkinter.CTkButton(master=param_window, text="Back", command=param_window.destroy)
    back_button.pack()
    back_button.place(relx=0.5, rely=0.9, anchor=CENTER)
    back_button.configure(font=("Courier", 16), fg_color="#0B1320")


# place the buttons in the window
background = Image.open("owasp.jpg")
background = background.resize((15, 15), Image.BICUBIC)
img_tk3 = customtkinter.CTkImage(background)

# place the about_param_spider button in the window
about_ParamSpider = customtkinter.CTkButton(master=root, text="about ParamSpider Tool", image=img_tk3, compound='left', command=about_params_spider, width=30, height=10)
about_ParamSpider.pack()
about_ParamSpider.place(relx=0.63, rely=0.1, anchor=CENTER)
about_ParamSpider.configure(font=("Courier", 14), fg_color="#0B1320")


# place the buttons in the window
def about_Vulnerability_Scanner_Tool():
    # create a new window
    Scanner_window = customtkinter.CTkToplevel()
    # set the appearance mode
    customtkinter.set_appearance_mode("dark")
    # set the default color theme
    customtkinter.set_default_color_theme("dark-blue")
    # set the title of the window
    Scanner_window.title("About Web Crawling Tool")
    # set the window size
    Scanner_window.geometry("1500x1000")
    # open the image file
    background_image_for_about_vulnerability_scanner_tool = Image.open("background1.jpg")
    # resize the image to fit the window size
    background_image_for_about_vulnerability_scanner_tool = background_image_for_about_vulnerability_scanner_tool.resize((Scanner_window.winfo_screenwidth(), Scanner_window.winfo_screenheight()), Image.BICUBIC)
    # create a PhotoImage object from the resized image
    background_image_for_about_vulnerability_scanner_tool = ImageTk.PhotoImage(background_image_for_about_vulnerability_scanner_tool)
    # create a Label widget with the image as background
    background_image_for_about_vulnerability_scanner_tool = customtkinter.CTkLabel(Scanner_window, image=background_image_for_about_vulnerability_scanner_tool)
    # place the label in the center of the window
    background_image_for_about_vulnerability_scanner_tool.place(x=0, y=0, relwidth=1, relheight=1)
    # the label that contains the information about the vulnerability scanner tool
    about_web_crawling_tool=customtkinter.CTkLabel(Scanner_window, text="Vulnerability scanner tools are designed to identify and assess security vulnerabilities in software applications, networks, or systems.\n Two common types of vulnerabilities that are often targeted are SQL injection and cross-site scripting (XSS).\n Here's an overview of each vulnerability and their corresponding scanner tools:\n"
                                                                         "\n 1-) SQL Injection: SQL injection is a type of attack that allows an attacker to execute malicious SQL statements against a database.\n This can result in the attacker gaining access to sensitive information or modifying data in the database.\n SQL injection vulnerabilities can be identified using tools such as SQLMap and SQLNinja.\n"
                                                                         "\n 2-) Cross-site scripting (XSS): Cross-site scripting (XSS) is a type of attack\n that allows an attacker to inject malicious scripts into a website.\n These scripts can then be executed by other users who visit the website,\n allowing the attacker to steal user data or hijack user sessions.\n XSS vulnerabilities can be identified using tools such as XSSer and XSStrike.\n")
# place the label in the center of the window
    about_web_crawling_tool.pack(fill="both", expand=True)
    about_web_crawling_tool.place(relx=0.5, rely=0.5, anchor=CENTER)
    about_web_crawling_tool.configure(font=("Courier", 16), fg_color="#0B1320")
    # create a back button
    back_button = customtkinter.CTkButton(master=Scanner_window, text="Back", command=Scanner_window.destroy)
    back_button.pack()
    back_button.place(relx=0.5, rely=0.9, anchor=CENTER)
    back_button.configure(font=("Courier", 16), fg_color="#0B1320")


# place the buttons in the window
background3 = Image.open("owasp.jpg")
background3 = background3.resize((15, 15), Image.BICUBIC)
img_tk4 = customtkinter.CTkImage(background3)

about_Vuln_Scanner = customtkinter.CTkButton(master=root, text="about Vuln Scanner Tool", image=img_tk4, compound='left', command=about_Vulnerability_Scanner_Tool, width=30, height=10)
about_Vuln_Scanner.pack()
about_Vuln_Scanner.place(relx=0.88, rely=0.1, anchor=CENTER)
about_Vuln_Scanner.configure(font=("Courier", 14), fg_color="#0B1320")


# place the buttons in the window
def about_password_operations():
    # create a new window
    password_window = customtkinter.CTkToplevel()
    # set the appearance mode
    customtkinter.set_appearance_mode("dark")
    # set the default color theme
    customtkinter.set_default_color_theme("dark-blue")
    # set the title of the window
    password_window.title("About Password Operations Tool")
    # set the window size
    password_window.geometry("1500x1000")
    # open the image file
    background_image_for_about_password_operations_tool = Image.open("background1.jpg")
    # resize the image to fit the window size
    background_image_for_about_password_operations_tool = background_image_for_about_password_operations_tool.resize((password_window.winfo_screenwidth(), password_window.winfo_screenheight()), Image.BICUBIC)
    # create a PhotoImage object from the resized image
    background_image_for_about_password_operations_tool_object = ImageTk.PhotoImage(background_image_for_about_password_operations_tool)
    # create a Label widget with the image as background
    background_image_for_about_password_operations_tool_label = customtkinter.CTkLabel(password_window, image=background_image_for_about_password_operations_tool_object)
    # place the label in the center of the window
    background_image_for_about_password_operations_tool_label.place(x=0, y=0, relwidth=1, relheight=1)
    # the label that contains the information about the password operations tool
    about_password_tool_label = customtkinter.CTkLabel(password_window, text="this Tool is made to help with Password Operations the features that this Tool include is :\n"
                                                            "\n Hashes Cracker : is a program that tries to find the original plaintext of a hashed message or password.\n Hashing is a one-way process of encoding data \n in such a way that it becomes almost impossible to recover the original data.\n A hash cracker tool can be used to test the strength of a password\n by attempting to crack the hashed password. It uses brute force\n"
                                                            "\n Password Generator : A password generator tool is a software program or application\n that creates complex and secure passwords automatically.\n It allows users to choose different parameters for the password, such as:\n length, character types, and more,\n to generate a strong and unique password that is difficult to guess.")
# place the label in the center of the window
    about_password_tool_label.pack(fill="both", expand=True)
    about_password_tool_label.place(relx=0.5, rely=0.5, anchor=CENTER)
    about_password_tool_label.configure(font=("Courier", 18), fg_color="#0B1320")
    # create a back button
    back_button = customtkinter.CTkButton(master=password_window, text="Back", command=password_window.destroy)
    back_button.pack()
    back_button.place(relx=0.5, rely=0.9, anchor=CENTER)
    back_button.configure(font=("Courier", 16), fg_color="#0B1320")


# place the background image of the button
background4 = Image.open("owasp.jpg")
background4 = background4.resize((15, 15), Image.BICUBIC)
img_tk5 = customtkinter.CTkImage(background4)

# place the about_password_button in the window
about_Password_button = customtkinter.CTkButton(master=root, text="About Password Tool", image=img_tk5, compound='left', command=about_password_operations, width=30, height=10)
about_Password_button.pack()
about_Password_button.place(relx=0.13, rely=0.1, anchor=CENTER)
about_Password_button.configure(font=("Courier", 14), fg_color="#0B1320")

# place the buttons in the window
Password_Operation_Button.pack(side="left", anchor=NW, fill="x", expand=True)

# place the buttons in the window
Scraping_button.pack(side="left", anchor=NW, fill="x", expand=True)

# place the buttons in the window
ParamSpider_button.pack(side="left", anchor=NW, fill="x", expand=True)

# place the buttons in the window
Vulnerability_Scanner_button.pack(side="left", anchor=NW, fill="x", expand=True)

# starting the main loop
root.mainloop()
