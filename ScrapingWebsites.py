import re
import urllib

import requests
from PIL import Image, ImageTk
from bs4 import BeautifulSoup
import tkinter as tk
import threading
from tkinter import filedialog, messagebox
import customtkinter
from ui_utils import open_image
from session_state import (
    get_target,
    set_target,
    is_url_in_scope,
    scope_error,
    describe_scope,
)

def scraping_tool():
    # Create a window
    root = customtkinter.CTkToplevel()
    # set the size of the window
    root.geometry("1000x1000")
    # set the appearance mode
    customtkinter.set_appearance_mode('dark')
    # set the default color theme
    customtkinter.set_default_color_theme('green')
    # set the title of the window
    root.title('Web Scraper')
    # Create a background image
    bckgrnd_img1 = open_image('background1.jpg')
    # resize the image to fit the window size
    bckgrnd_img1 = bckgrnd_img1.resize((root.winfo_screenwidth(), root.winfo_screenheight()), Image.BICUBIC)
    # convert the image to a TkPhoto object
    bckgrnd_img1 = ImageTk.PhotoImage(bckgrnd_img1)
    # Create a Label widget with the image as background
    background_label1 = tk.Label(root, image=bckgrnd_img1)
    # Place the Label widget of the window
    background_label1.place(x=0, y=0, relwidth=1, relheight=1)

    # Create the URL input field
    url_entry_frame = customtkinter.CTkFrame(root)
    # place the frame in the center of the window
    url_entry_frame.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
    # create the label
    url_label = customtkinter.CTkLabel(url_entry_frame, text='Enter the URL to scrape:')
    # place the label in the frame
    url_label.pack(side=customtkinter.LEFT)
    # create the entry field
    url_entry = customtkinter.CTkEntry(url_entry_frame)
    # place the entry field in the frame
    url_entry.pack(side=customtkinter.LEFT)
    if get_target():
        url_entry.insert(0, get_target())

    def load_global_target():
        target = get_target()
        if not target:
            messagebox.showinfo('Global Target', 'No global target configured.')
            return
        url_entry.delete(0, tk.END)
        url_entry.insert(0, target)

    sync_button = customtkinter.CTkButton(url_entry_frame, text='Use Global Target', command=load_global_target)
    sync_button.pack(side=customtkinter.LEFT, padx=5)

    scope_label = customtkinter.CTkLabel(root, text=describe_scope())
    scope_label.place(relx=0.5, rely=0.25, anchor=customtkinter.CENTER)
    # create the button
    # Create the checkboxes for selection
    checkboxes_frame = customtkinter.CTkFrame(root)
    # place the frame in the center of the window
    checkboxes_frame.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
    # create the booleanvar for the checkboxes
    links_checkbox_var = customtkinter.BooleanVar()
    # create the checkbox
    links_checkbox = customtkinter.CTkCheckBox(checkboxes_frame, text='Links', variable=links_checkbox_var)
    # place the checkbox in the frame
    links_checkbox.pack(side=customtkinter.LEFT)
    # create the booleanvar for the checkboxes
    images_checkbox_var = customtkinter.BooleanVar()
    # create the checkbox
    images_checkbox = customtkinter.CTkCheckBox(checkboxes_frame, text='Images', variable=images_checkbox_var)
    # place the checkbox in the frame
    images_checkbox.pack(side=customtkinter.LEFT)

    social_media_checkbox_var = customtkinter.BooleanVar()
    # Create the checkbox
    social_media_checkbox = customtkinter.CTkCheckBox(checkboxes_frame, text='Social Media Links',
                                                      variable=social_media_checkbox_var)
    # Place the checkbox in the frame
    social_media_checkbox.pack(side=customtkinter.LEFT)

    # legal warning label
    legal_warning = customtkinter.CTkLabel(root,
                                           text='Legal warning: \n This app is for educational purposes only. \n Do not use it to scrape websites that you do not own or have permission to scrape.')
    legal_warning.place(relx=0.5, rely=0.7, anchor=customtkinter.CENTER)
    # set the font of the label
    legal_warning.configure(font=("Courier", 14))

    # how to use the app
    how_to_use = customtkinter.CTkLabel(root,
                                        text='How to use the app: \n 1. Enter the URL of the website you want to scrape. \n 2. Select the data you want to scrape. \n 3. Click the Scrape button. \n 4. Click the Save button to save the output to a file.')
    how_to_use.place(relx=0.5, rely=0.6, anchor=customtkinter.CENTER)
    # set the font of the label
    how_to_use.configure(font=("Courier", 14))

    # Create the progress label
    processing_label = customtkinter.CTkLabel(root, text="")
    # Place the label in the center of the window
    processing_label.pack()

    # Create output label
    output_label = customtkinter.CTkLabel(root, text='')
    # Place the label in the center of the window
    output_label.pack()

    # Function to scrape data based on user selection
    def scrape_data():
        # Get the URL from the user input
        url = url_entry.get()
        processing_label.configure(text="Processing... Please wait")

        if not is_url_in_scope(url):
            messagebox.showerror('Scope Restriction', scope_error(url))
            processing_label.configure(text="")
            return
        set_target(url)
        scope_label.configure(text=describe_scope())

        # Get the selected options
        selected_options = []
        if links_checkbox_var.get():
            selected_options.append('links')
        if images_checkbox_var.get():
            selected_options.append('images')
        if social_media_checkbox_var.get():
            selected_options.append('social_media')

        if not selected_options:  # No checkboxes selected
            output_label.configure(text='Please select at least one checkbox.')
            processing_label.configure(text="")
            return
        else:
            output_label.configure(text='')

            # Create a new thread to run the web scraping code
        t = threading.Thread(target=scrape_data_thread, args=(selected_options, url))
        t.start()

    def on_checkbox_change(*args):
        output_label.configure(text='')  # Clear the error message

    # Bind the callback function to the checkbox variables
    links_checkbox_var.trace('w', on_checkbox_change)
    images_checkbox_var.trace('w', on_checkbox_change)
    social_media_checkbox_var.trace('w', on_checkbox_change)

    def is_social_media_link(link):
        social_media_domains = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com']
        for domain in social_media_domains:
            if domain in link:
                return True
        return False
    # Function to scrape data in a separate thread
    def scrape_data_thread(selected_options, url):
        try:
            # Send a request to the website you want to scrape
            response = requests.get(url)

            # Parse the HTML content of the website using BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
        except requests.exceptions.RequestException as e:
            output_label.configure(text=f'Error: {e}')
            processing_label.configure(text="")
            return

        # Extract data from the website based on user selection
        output_text = ''
        link_tags = []
        for option in selected_options:
            if option == 'links':
                link_tags = soup.find_all('a')
                output_text += 'Links:\n'
                for link in link_tags:
                    href = link.get('href')
                    if href:
                        full_url = urllib.parse.urljoin(url, href)
                        output_text += f'{full_url}\n'
            elif option == 'images':
                data = soup.find_all('img')
                output_text += 'Images:\n'
                for img in data:
                    src = img.get('src')
                    if src:
                        full_url = urllib.parse.urljoin(url, src)
                        output_text += f'{full_url}\n'


            elif option == 'social_media':
                # Extract social media links
                social_media_links = []
                for tag in soup.find_all('a'):
                    href = tag.get('href')
                    if href and is_social_media_link(href):
                        full_url = urllib.parse.urljoin(url, href)
                        social_media_links.append(full_url)
                output_text += 'Social Media Links:\n'
                for link in social_media_links:
                    output_text += f'{link}\n'

        processing_label.configure(text="")
        # Create a new window to display the output
        output_window = customtkinter.CTkToplevel(root)

        output_window.geometry("1000x1000")

        # Create a scrollbar for the output window
        scrollbar = tk.Scrollbar(output_window)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create a text box for the output
        output_box = tk.Text(output_window, wrap=tk.WORD, yscrollcommand=scrollbar.set, bg="black", fg="white")
        output_box.pack()

        # Add the output to the text box
        output_box.insert(tk.END, output_text)

        # Make the links clickable
        if link_tags:
            for link in link_tags:
                href = link.get('href')
                if href:
                    full_url = urllib.parse.urljoin(url, href)
                    output_box.insert(tk.END, full_url + '\n')
                    start_index = output_box.search(full_url, '1.0', tk.END)
                    if start_index:
                        end_index = f'{start_index}+{len(full_url)}c'
                        tag_name = f"link_{start_index}"
                        output_box.tag_add(tag_name, start_index, end_index)
                        output_box.tag_config(tag_name, foreground='white', underline=True)
                        output_box.tag_bind(tag_name, '<Button-1>', lambda event, href=full_url: open_link(href))

        # Save the output to a file
        save_button = customtkinter.CTkButton(output_window, text='Save', command=lambda: save_file(output_text))
        save_button.pack()

    # Function to open a link in the default web browser
    def open_link(href):
        import webbrowser
        webbrowser.open_new_tab(href)

    # Function to save the output to a file
    def save_file(output_text):
        filename = filedialog.asksaveasfilename(defaultextension='.txt')
        if filename:
            with open(filename, 'w') as f:
                f.write(output_text)
            output_label.configure(text=f'File saved as {filename}.')
        else:
            output_label.configure(text='No file selected.')

    def back():
        root.destroy()

    # Create the scrape button
    scrape_button = customtkinter.CTkButton(root, text='Scrape', command=scrape_data)
    scrape_button.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    # Create the back button
    back_button = customtkinter.CTkButton(root, text='Back', command=back)
    back_button.place(relx=0.5, rely=0.9, anchor=tk.CENTER)

    # Start the GUI
    root.mainloop()

