import threading
import urllib
from tkinter import *
import json
from concurrent.futures import ThreadPoolExecutor
import re
import random
from urllib import response
from PIL import ImageTk
from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse, parse_qs, urlencode
from urllib.parse import quote
import customtkinter as ctk
from PIL import Image


def param_spider_tool():
    # set the appearance mode
    ctk.set_appearance_mode("dark")
    # set the default color theme
    ctk.set_default_color_theme("dark-blue")
    # create a window
    param_spider_window = ctk.CTkToplevel()
    # set the title of the window
    param_spider_window.geometry("1000x700")
    # set the title of the window
    param_spider_window.title("Parameter Spider Tool")
    # set the background color of the window
    param_spider_window.configure(bg="#1e88e5")
    # set the window to be resizable
    param_spider_window.resizable(True, True)

    # Open the image file
    img = Image.open("dark.png")

    # Resize the image to fit the window size
    img = img.resize((param_spider_window.winfo_screenwidth(), param_spider_window.winfo_screenheight()), Image.BICUBIC)
    img = img.convert('RGB')
    # Create a PhotoImage object from the resized image
    bg_img = ImageTk.PhotoImage(img)

    # Create a Label widget with the image as background
    bg_label = ctk.CTkLabel(param_spider_window, image=bg_img)
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    def paramSpider():

        user_agent_list = [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
        ]

        user_agent = random.choice(user_agent_list)

        fetched_url = []
        common_fetched_url = set()
        valid_urls = set()

        # Taking user inputs
        domain = url_entry.get()
        max_thread = thread_entry.get()
        max_link_to_scan = links_to_search_entry.get()

        print("=>>> We just started! Give us some time!")

        if len(max_link_to_scan) == 0:
            max_link_to_scan = 10000

        allurl = set()

        try:
            # Capturing API results to get URLs
            alienvault_request_fetch = requests.get(
                'https://otx.alienvault.com/api/v1/indicators/hostname/' + urllib.parse.quote(
                    domain) + '/url_list?limit=1000',
                headers={'User-Agent': user_agent}, timeout=5).json()
            for request_url in alienvault_request_fetch['url_list']:
                if alienvault_request_fetch.status_code == 200:
                    allurl.add(request_url['url'])
                    for characters in request_url['url']:
                        if '?' and '=' and '/' in characters:
                            common_fetched_url.add(request_url['url'])
                        else:
                            pass
        except:
            pass
        # wayback machine
        waybackURL = "https://web.archive.org/cdx/search/cdx?url=*." + domain + "&output=json&fl=original&collapse=urlkey"

        try:

            response = requests.get(waybackURL, headers={'User-Agent': user_agent}, timeout=5)
            if response.status_code == 200:
                load = json.loads(response.text)
                for ur in load:
                    for char in ur[0]:
                        allurl.add(ur[0])
                        if '?' and '=' and '/' in char:
                            common_fetched_url.add(ur[0])
                        else:
                            pass
        except:
            pass

        # printing all the parameters links that we found in the main domain
        for i in allurl:
            if '?' in i:
                print(i)
        print("=>>> We found " + str(len(allurl)) + " URLs from the API results")


        link_count = 0
        # Formatting the URLs
        for url in common_fetched_url:
            try:
                urlpara = url.split("?")[1]
                urlpara2 = urlpara.split("&")
                for parameters in urlpara2:
                    para_index = parameters.split("=")
                    para_string = str(para_index[0] + "=" + para_index[1])
                    # param_check = str(para_index[0]) + "=" + str(para_index[1]).replace(str(para_index[1]), 'anything')
                    formatted_url = url.replace(para_string)
                    fetched_url.append(formatted_url)
                    link_count += 1

                if para_string not in fetched_url:
                    fetched_url.append(para_string)
                    link_count += 1

                    # Send GET request to the URL
                    response = requests.get(url, headers={'User-Agent': user_agent}, timeout=5)
                    # Check if the maximum number of links to scan has been reached
                    if link_count == int(max_link_to_scan):
                        break
            except:
                pass

        print("==>>> We will be scanning " + str(len(fetched_url)) + " links!")

        # Scan for reflected keyword
        def sanitize_input(input_data):
            """
            Sanitize input data using a whitelist approach
            """
            allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-')
            return ''.join(c for c in input_data if c in allowed_chars)

        def validate_xss(url):
            try:
                headers = {'User-Agent': user_agent}
                response = requests.get(url, headers=headers, timeout=1)
                response.encoding = 'utf-16'  # Set the character encoding when decoding the response
                soup = BeautifulSoup(response.content, 'html.parser')
                # Search for script tags and attributes that might contain XSS payloads
                script_tags = soup.find_all('script', )
                script_attributes = [attr for tag in soup.find_all() for attr in tag.attrs if re.match('^on', attr)]

                # Check for known malicious payloads using a blacklist approach
                blacklist = ['<script>alert("XSS")</script>', '<img src=x onerror=alert("XSS")>']
                for tag in script_tags + script_attributes:
                    for payload in blacklist:
                        if payload in str(tag):
                            with open("file.txt", "w", encoding="utf-16") as f:
                                f.write(f" Possible (XSS) vulnerability found in {url} with payload: {payload} \n")
                            return f" Possible (XSS) vulnerability found in {url} with payload: {payload}"

                    # Validate all input data and output encoding using a whitelist approach
                for tag in soup.find_all():
                    for attr, value in tag.attrs.items():
                        # Sanitize input data
                        sanitized_value = sanitize_input(value)
                        if sanitized_value != value:
                            return f"Input validation failed in {url} for tag: {tag}, attribute: {attr}, value: {value}"

                return None
            except:
                pass

        found_links = set()
        open_redirect = set()

        if len(max_thread) == 0:
            max_thread = 1000

        try:
            with ThreadPoolExecutor(max_workers=int(max_thread)) as pool:
                response_list = list(pool.map(validate_xss, fetched_url))
            file_write = []
            for r in response_list:
                if r is not None:
                    found_links.add(r)
                    if 'url' and '=http' in r:
                        open_redirect.add(r)
        except:
            pass

            # Showing results
        if len(found_links) != 0:
            print('\n#######################-  Possible XSS   -###########################')
            for links1 in found_links:
                print(links1)
            print('\n#######################-  Possible Open Redirect   -###########################')
            if len(open_redirect) != 0:
                for links in open_redirect:
                    print(links)
            elif len(open_redirect) == 0:
                print("No links found!")
        elif len(found_links) == 0:
            print('\n#######################-  Result   -###########################')
            print('We could not find anything :( ')
        with open('url.txt', 'w', encoding='utf-16') as f:
            for urls in allurl:
                f.write('%s\n' % urls)
        print("URLs are saved")
        label2.configure(text=
                                '\n#######################-  the results has been saved to a file named "url-%s.txt"! \n and the possible XSS URLs are in a file called (file.txt)   -###########################' % str(
                                    domain))
        label.configure(text="Request completed!!", font=("Courier", 15))

    # Thread
    def thread():
        # Update the status label to indicate that the program is running
        label.configure(text='Processing.....', font=("Courier", 15))
        # creating a list of threads
        threads = []
        # creating threads
        t = threading.Thread(target=paramSpider)
        # adding threads to the list
        threads.append(t)
        # starting threads
        t.start()

    def back():
        param_spider_window.destroy()

    # GUI
    url_label = ctk.CTkLabel(master=param_spider_window, text="Enter URL :")
    # pack the label
    url_label.pack(side="left", anchor=NW, expand=True)
    # palce the label
    url_label.place(relx=0.01, rely=0)
    # configure the label
    url_label.configure(font=("Courier", 12), fg_color="black")
    # create the Entry
    url_entry = ctk.CTkEntry(master=param_spider_window)
    # pack the entry
    url_entry.pack(side="left", anchor=NE, expand=True)
    # pack the entry
    url_entry.place(relx=0.12, rely=0)
    # create the button
    thread_label = ctk.CTkLabel(master=param_spider_window, text="MAX Threads to use\nDefault(1000) :")
    # pack the label
    thread_label.pack(side="left", anchor=NW, expand=True)
    # configure the label
    thread_label.place(relx=0.3, rely=0)
    # configure the label
    thread_label.configure(font=("Courier", 12), fg_color="black")
    # create the button
    thread_entry = ctk.CTkEntry(master=param_spider_window)
    # pack the entry
    thread_entry.pack(side="left", anchor=NW, expand=True)
    # pack the entry
    thread_entry.place(relx=0.44, rely=0)
    # create the button
    lniks_to_search_label = ctk.CTkLabel(master=param_spider_window,
                                         text="how many links\nyou want to scan\n(default 1000) :")
    # pack the label
    lniks_to_search_label.pack(side="left", anchor=NW, expand=True)
    # configure the label
    lniks_to_search_label.configure(font=("Courier", 12), fg_color="black")
    # pack the label
    lniks_to_search_label.place(relx=0.61, rely=0)
    # create the button
    links_to_search_entry = ctk.CTkEntry(master=param_spider_window)
    # pack the entry
    links_to_search_entry.pack(side="left", anchor=NW, expand=True)
    # pack the entry
    links_to_search_entry.place(relx=0.75, rely=0)
    # create the button
    label = ctk.CTkLabel(master=param_spider_window, text="not Running")
    # configure the label
    label.configure(font=("Courier", 15), fg_color="black")
    # pack the label
    label.pack(side="left", anchor=NW, expand=True)
    # pack the label
    label.place(relx=0.46, rely=0.7)
    # create the button
    label2 = ctk.CTkLabel(master=param_spider_window)
    # configure the label
    label2.configure(font=("Courier", 12))
    # pack the label
    label2.place(relx=0.5, rely=0.1, anchor=CENTER)
    # create the button
    legal_warnning_label = ctk.CTkLabel(master=param_spider_window,
                                        text="Legal Warning:\nUsage of this tool for attacking targets without prior mutual consent is illegal.\nIt is the end user's responsibility to obey all applicable federal laws.\nDevelopers assume no liability\n and are not responsible for any misuse or damage caused by this program")
    # configure the label
    legal_warnning_label.configure(font=("Courier", 16))
    # pack the label
    legal_warnning_label.pack(fill='both', expand=True, side='bottom')
    # place the label
    legal_warnning_label.place(relx=0.5, rely=0.9, anchor=CENTER)
    # create the label
    how_to_use_label = ctk.CTkLabel(master=param_spider_window,
                                    text="How to use:\n1-Enter the URL you want to scan (ex: orange.com)\n2-Enter the number of threads you want to use(ex:100)\n3-Enter the number of links you want to scan(ex: 100)\n4-Click on start program")
    # configure the label
    how_to_use_label.configure(font=("Courier", 20))
    # place the label
    how_to_use_label.place(relx=0.5, rely=0.5, anchor=CENTER)
    # open the image
    image = Image.open("owasp.jpg")
    # resize the image
    image = image.resize((15, 15), Image.ANTIALIAS)
    # convert image to tkinter readable image format
    photo = ImageTk.PhotoImage(image)
    # create the button
    start_program_button = ctk.CTkButton(master=param_spider_window, image=photo, text="Start Program", command=thread)
    # place the button
    start_program_button.place(relx=0.5, rely=0.8, anchor=CENTER)
    # create the back button
    back_button = ctk.CTkButton(master=param_spider_window, text="Back", command=back)
    # place the button
    back_button.place(relx=0.35, rely=0.8, anchor=CENTER)
    # start the GUI
    param_spider_window.mainloop()
