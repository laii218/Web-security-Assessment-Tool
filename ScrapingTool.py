from tkinter import *

from PIL import ImageTk
from PIL import Image
from adminpagesFinder import admin_finder
from vulnerabilitySearch import new_window
from ScrapingWebsites import scraping_tool
import customtkinter as ctk


def scraping():

    second_window = ctk.CTkToplevel()

    ctk.set_appearance_mode("dark")

    ctk.set_default_color_theme("dark-blue")

    second_window.geometry("1500x700")

    second_window.title("Scraping Tool")

    # Open the image file
    img = Image.open("dark.png")

    # Resize the image to fit the window size
    img = img.resize((second_window.winfo_screenwidth(), second_window.winfo_screenheight()), Image.ANTIALIAS)
    # convert the image to a TkPhoto object
    img = img.convert('RGB')
    # Create a PhotoImage object from the resized image
    bg_img = ImageTk.PhotoImage(img)

    # Create a Label widget with the image as background
    bg_label = ctk.CTkLabel(second_window, image=bg_img)
    # Place the Label widget of the window
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)
    # Create a function to destroy the window
    def destroy():
        # destroy the window
        second_window.destroy()
    # create the image button
    background13 = Image.open("dark.png")
    # Resize the image to fit the window size
    background13 = background13.resize((15, 15), Image.BICUBIC)
    # Create a PhotoImage object from the resized image
    something3 = ctk.CTkImage(background13)
    # create the button
    back_button = ctk.CTkButton(master=second_window,image=something3, text="go back", command=destroy)
    # place the button in the center of the window
    back_button.pack(side="left", padx=10, pady=10)
    # place the button in the center of the window
    back_button.place(relx=0.1, rely=0)
    # set the button font
    background12 = Image.open("dark.png")
    # Resize the image to fit the window size
    background10 = background12.resize((15, 15), Image.BICUBIC)
    # Create a PhotoImage object from the resized image
    something2 = ctk.CTkImage(background12)
    # create the button
    admin_finder_button = ctk.CTkButton(master=second_window,image=something2, text="admin pages finder", command=admin_finder)
    # place the button in the center of the window
    admin_finder_button.pack()
    # place the button in the center of the window
    admin_finder_button.place(relx=0.3, rely=0)
    # set the button font
    how_to_use_label = ctk.CTkLabel(master=second_window, text="How to use: \n1. this is a tool that contains multiple features \n2. you can use it to find admin pages in a website \n3. you can use it to search for vulnerabilities information \n4. you can use it to scrape a website \n")
    # place the label in the center of the window
    how_to_use_label.place(relx=0.5, rely=0.5, anchor="center")
    # set the label font
    how_to_use_label.configure(font=("Courier", 20))
    # set the label color
    legal_warning_label = ctk.CTkLabel(master=second_window, text="Legal Warning: \n1. this tool is for educational purposes only \n2. you are responsible for your own actions \n3. the author is not responsible for any misuse or damage caused \n4. this tool is not intended to be used for illegal purposes \n")
    # place the label in the center of the window
    legal_warning_label.place(relx=0.5, rely=0.7, anchor="center")
    # set the label font
    legal_warning_label.configure(font=("Courier", 20))
    # set the image for the button
    background11 = Image.open("dark.png")
    # Resize the image to fit the window size
    background11 = background11.resize((15, 15), Image.BICUBIC)
    # Create a PhotoImage object from the resized image
    something1 = ctk.CTkImage(background11)
    # create the button
    start = ctk.CTkButton(second_window,image=something1, text="Scraping Tool", command=scraping_tool)
    # place the button in the center of the window
    start.pack()
    # place the button in the center of the window
    start.place(relx=0.5, rely=0)
    background10 = Image.open("dark.png")
    # Resize the image to fit the window size
    background10 = background10.resize((15, 15), Image.BICUBIC)
    # Create a PhotoImage object from the resized image
    something = ctk.CTkImage(background10)
    # create the button
    cve_search = ctk.CTkButton(master=second_window,image=something, text="Vulnerabilities Search", command=new_window)
    # place the button in the center of the window
    cve_search.pack()
    # place the button in the center of the window
    cve_search.place(relx=0.7, rely=0)
    # start the main loop
    second_window.mainloop()
