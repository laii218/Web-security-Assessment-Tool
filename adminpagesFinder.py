from tkinter.filedialog import asksaveasfilename
import requests
import threading
import customtkinter as ctk
from tkinter import messagebox, filedialog
import tkinter as tk
from urllib.parse import urlsplit

from PIL import Image, ImageTk
from ui_utils import open_image
from session_state import (
    get_target,
    set_target,
    is_url_in_scope,
    scope_error,
    describe_scope,
)

REQUEST_TIMEOUT = 10


# Define a function to find admin pages
def admin_finder():
    # Create a GUI window
    root = ctk.CTkToplevel()
    # set the apperaance mode
    ctk.set_appearance_mode('dark')
    # set the default color theme
    ctk.set_default_color_theme('dark-blue')
    # set the title of the window
    root.title('Admin Page Finder')
    # set the size of the window
    root.geometry('1500x1000')
    # set the image of the window
    bckgrnd_img = open_image('dark.png')
    # resize the image to fit the window size
    bckgrnd_img = bckgrnd_img.resize((root.winfo_screenwidth(), root.winfo_screenheight()), Image.BICUBIC)
    # convert the image to a TkPhoto object
    bckgrnd_img = ImageTk.PhotoImage(bckgrnd_img)
    # Create a Label widget with the image as background
    background_label = tk.Label(root, image=bckgrnd_img)
    # Place the Label widget of the window
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    # Create a Label widget for the URL input
    url_label = ctk.CTkLabel(root, text='Enter URL:')
    # Place the Label widget of the window
    url_label.place(relx=0.3, rely=0.3, anchor='center')
    # Create an Entry widget for the URL input
    url_entry = ctk.CTkEntry(root, width=200)
    # Place the Entry widget of the window
    url_entry.place(relx=0.5, rely=0.3, anchor='center')
    if get_target():
        url_entry.insert(0, get_target())

    def load_global_target():
        target = get_target()
        if not target:
            messagebox.showinfo('Global Target', 'No global target configured.')
            return
        url_entry.delete(0, tk.END)
        url_entry.insert(0, target)

    sync_button = ctk.CTkButton(root, text='Use Global Target', command=load_global_target)
    sync_button.place(relx=0.7, rely=0.25, anchor='center')
    # Create a Label widget for the status message
    status_label = ctk.CTkLabel(root, text='Not running', padx=5)
    # Place the Label widget of the window
    status_label.place(relx=0.5, rely=0.4, anchor='center')
    scope_label = ctk.CTkLabel(root, text=describe_scope())
    scope_label.place(relx=0.5, rely=0.35, anchor='center')
    # Create a Listbox widget to display the admin pages
    listbox = tk.Listbox(root, height=10, width=50)
    # Place the Listbox widget of the window
    listbox.pack(side='top', anchor='center')
    # create a how_to_use label
    how_to_use = ctk.CTkLabel(root, text='How to use: \nEnter the URL of the website you want to scan for admin pages.\n Then click the "Start" button to start the scan.\n Once the scan is complete, click the "Save" button to save the results to a text file.\n and you can upload direcotry list to scan for admin pages using the upload option.')
    # Place the Label widget of the window
    how_to_use.place(relx=0.5, rely=0.6, anchor='center')
    # configure the label
    how_to_use.configure(font=("Courier", 14), fg_color="#0B1320")
    # create a legal warnning label
    legal_warnning = ctk.CTkLabel(root, text='Legal Warnning: \nThis tool is for educational purposes only. You are responsible for your own actions. If you mess something up or break any laws while using this software, it\'s your fault, and your fault only.')
    # Place the Label widget of the window
    legal_warnning.place(relx=0.5, rely=0.7, anchor='center')
    # configure the label
    legal_warnning.configure(font=("Courier", 14), fg_color="#0B1320")

    # Define a list of directories to check
    directories = ('admin', 'dashboard', 'login', 'wp-admin', 'backend', 'admin/', 'admin/login', 'administrator/','login.php','administration/','admin1/','admin2/','admin3/','admin4/','admin5/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/',
'memberadmin/','administratorlogin/','adm/','account.asp','admin/account.asp','admin/index.asp','admin/login.asp','admin/admin.asp','/login.aspx',
'admin_area/admin.asp','admin_area/login.asp','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/admin.html','admin_area/login.html','admin_area/index.html','admin_area/index.asp','bb-admin/index.asp','bb-admin/login.asp','bb-admin/admin.asp',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','admin/controlpanel.html','admin.html','admin/cp.html','cp.html',
'administrator/index.html','administrator/login.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html','moderator.html',
'moderator/login.html','moderator/admin.html','account.html','controlpanel.html','admincontrol.html','admin_login.html','panel-administracion/login.html',
'admin/home.asp','admin/controlpanel.asp','admin.asp','pages/admin/admin-login.asp','admin/admin-login.asp','admin-login.asp','admin/cp.asp','cp.asp',
'administrator/account.asp','administrator.asp','acceso.asp','login.asp','modelsearch/login.asp','moderator.asp','moderator/login.asp','administrator/login.asp',
'moderator/admin.asp','controlpanel.asp','admin/account.html','adminpanel.html','webadmin.html','administration','pages/admin/admin-login.html','admin/admin-login.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','user.asp','user.html','admincp/index.asp','admincp/login.asp','admincp/index.html',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','adminarea/index.html','adminarea/admin.html','adminarea/login.html',
'panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html','admin/admin_login.html',
'admincontrol/login.html','adm/index.html','adm.html','admincontrol.asp','admin/account.asp','adminpanel.asp','webadmin.asp','webadmin/index.asp',
'webadmin/admin.asp','webadmin/login.asp','admin/admin_login.asp','admin_login.asp','panel-administracion/login.asp','adminLogin.asp',
'admin/adminLogin.asp','home.asp','admin.asp','adminarea/index.asp','adminarea/admin.asp','adminarea/login.asp','admin-login.html',
'panel-administracion/index.asp','panel-administracion/admin.asp','modelsearch/index.asp','modelsearch/admin.asp','administrator/index.asp',
'admincontrol/login.asp','adm/admloginuser.asp','admloginuser.asp','admin2.asp','admin2/login.asp','admin2/index.asp','adm/index.asp',
'adm.asp','affiliate.asp','adm_auth.asp','memberadmin.asp','administratorlogin.asp','siteadmin/login.asp','siteadmin/index.asp','siteadmin/login.html','memberadmin/','administratorlogin/','adm/','admin/account.php','admin/index.php','admin/login.php','admin/admin.php','admin/account.php',
'admin_area/admin.php','admin_area/login.php','siteadmin/login.php','siteadmin/index.php','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.php','bb-admin/index.php','bb-admin/login.php','bb-admin/admin.php','admin/home.php','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.php','admin.php','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.php','cp.php','administrator/index.php','administrator/login.php','nsw/admin/login.php','webadmin/login.php','admin/admin_login.php','admin_login.php',
'administrator/account.php','administrator.php','admin_area/admin.html','pages/admin/admin-login.php','admin/admin-login.php','admin-login.php',
'bb-admin/index.html','bb-admin/login.html','acceso.php','bb-admin/admin.html','admin/home.html','login.php','modelsearch/login.php','moderator.php','moderator/login.php',
'moderator/admin.php','account.php','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.php','admincontrol.php',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.php','adminarea/index.html','adminarea/admin.html',
'webadmin.php','webadmin/index.php','webadmin/admin.php','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.php','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.php','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.php','wp-login.php','adminLogin.php','admin/adminLogin.php','home.php','admin.php','adminarea/index.php',
'adminarea/admin.php','adminarea/login.php','panel-administracion/index.php','panel-administracion/admin.php','modelsearch/index.php',
'modelsearch/admin.php','admincontrol/login.php','adm/admloginuser.php','admloginuser.php','admin2.php','admin2/login.php','admin2/index.php','usuarios/login.php',
'adm/index.php','adm.php','affiliate.php','adm_auth.php','memberadmin.php','administratorlogin.php','adm/','admin/account.cfm','admin/index.cfm','admin/login.cfm','admin/admin.cfm','admin/account.cfm',
'admin_area/admin.cfm','admin_area/login.cfm','siteadmin/login.cfm','siteadmin/index.cfm','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.cfm','bb-admin/index.cfm','bb-admin/login.cfm','bb-admin/admin.cfm','admin/home.cfm','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.cfm','admin.cfm','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.cfm','cp.cfm','administrator/index.cfm','administrator/login.cfm','nsw/admin/login.cfm','webadmin/login.cfm','admin/admin_login.cfm','admin_login.cfm',
'administrator/account.cfm','administrator.cfm','admin_area/admin.html','pages/admin/admin-login.cfm','admin/admin-login.cfm','admin-login.cfm',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.cfm','modelsearch/login.cfm','moderator.cfm','moderator/login.cfm',
'moderator/admin.cfm','account.cfm','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.cfm','admincontrol.cfm',
'admin/adminLogin.html','acceso.cfm','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.cfm','adminarea/index.html','adminarea/admin.html',
'webadmin.cfm','webadmin/index.cfm','webadmin/admin.cfm','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.cfm','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.cfm','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.cfm','wp-login.cfm','adminLogin.cfm','admin/adminLogin.cfm','home.cfm','admin.cfm','adminarea/index.cfm',
'adminarea/admin.cfm','adminarea/login.cfm','panel-administracion/index.cfm','panel-administracion/admin.cfm','modelsearch/index.cfm',
'modelsearch/admin.cfm','admincontrol/login.cfm','adm/admloginuser.cfm','admloginuser.cfm','admin2.cfm','admin2/login.cfm','admin2/index.cfm','usuarios/login.cfm',
'adm/index.cfm','adm.cfm','affiliate.cfm','adm_auth.cfm','memberadmin.cfm','administratorlogin.cfm','adminLogin/','admin_area/','panel-administracion/','instadmin/','login.aspx',
'memberadmin/','administratorlogin/','adm/','admin/account.aspx','admin/index.aspx','admin/login.aspx','admin/admin.aspx','admin/account.aspx',
'admin_area/admin.aspx','admin_area/login.aspx','siteadmin/login.aspx','siteadmin/index.aspx','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.aspx','bb-admin/index.aspx','bb-admin/login.aspx','bb-admin/admin.aspx','admin/home.aspx','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.aspx','admin.aspx','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.aspx','cp.aspx','administrator/index.aspx','administrator/login.aspx','nsw/admin/login.aspx','webadmin/login.aspx','admin/admin_login.aspx','admin_login.aspx',
'administrator/account.aspx','administrator.aspx','admin_area/admin.html','pages/admin/admin-login.aspx','admin/admin-login.aspx','admin-login.aspx',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.aspx','modelsearch/login.aspx','moderator.aspx','moderator/login.aspx',
'moderator/admin.aspx','acceso.aspx','account.aspx','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.aspx','admincontrol.aspx',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.aspx','adminarea/index.html','adminarea/admin.html',
'webadmin.aspx','webadmin/index.aspx','webadmin/admin.aspx','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.aspx','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.aspx','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.aspx','wp-login.aspx','adminLogin.aspx','admin/adminLogin.aspx','home.aspx','admin.aspx','adminarea/index.aspx',
'adminarea/admin.aspx','adminarea/login.aspx','panel-administracion/index.aspx','panel-administracion/admin.aspx','modelsearch/index.aspx',
'modelsearch/admin.aspx','admincontrol/login.aspx','adm/admloginuser.aspx','admloginuser.aspx','admin2.aspx','admin2/login.aspx','admin2/index.aspx','usuarios/login.aspx',
'adm/index.aspx','adm.aspx','affiliate.aspx','adm_auth.aspx','memberadmin.aspx','administratorlogin.aspx','memberadmin/','administratorlogin/','adm/','admin/account.js','admin/index.js','admin/login.js','admin/admin.js','admin/account.js',
'admin_area/admin.js','admin_area/login.js','siteadmin/login.js','siteadmin/index.js','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.js','bb-admin/index.js','bb-admin/login.js','bb-admin/admin.js','admin/home.js','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.js','admin.js','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.js','cp.js','administrator/index.js','administrator/login.js','nsw/admin/login.js','webadmin/login.js','admin/admin_login.js','admin_login.js',
'administrator/account.js','administrator.js','admin_area/admin.html','pages/admin/admin-login.js','admin/admin-login.js','admin-login.js',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.js','modelsearch/login.js','moderator.js','moderator/login.js',
'moderator/admin.js','account.js','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.js','admincontrol.js',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.js','adminarea/index.html','adminarea/admin.html',
'webadmin.js','webadmin/index.js','acceso.js','webadmin/admin.js','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.js','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.js','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.js','wp-login.js','adminLogin.js','admin/adminLogin.js','home.js','admin.js','adminarea/index.js',
'adminarea/admin.js','adminarea/login.js','panel-administracion/index.js','panel-administracion/admin.js','modelsearch/index.js',
'modelsearch/admin.js','admincontrol/login.js','adm/admloginuser.js','admloginuser.js','admin2.js','admin2/login.js','admin2/index.js','usuarios/login.js',
'adm/index.js','adm.js','affiliate.js','adm_auth.js','memberadmin.js','administratorlogin.js','bb-admin/index.cgi','bb-admin/login.cgi','bb-admin/admin.cgi','admin/home.cgi','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.cgi','admin.cgi','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.cgi','cp.cgi','administrator/index.cgi','administrator/login.cgi','nsw/admin/login.cgi','webadmin/login.cgi','admin/admin_login.cgi','admin_login.cgi',
'administrator/account.cgi','administrator.cgi','admin_area/admin.html','pages/admin/admin-login.cgi','admin/admin-login.cgi','admin-login.cgi',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.cgi','modelsearch/login.cgi','moderator.cgi','moderator/login.cgi',
'moderator/admin.cgi','account.cgi','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.cgi','admincontrol.cgi',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.cgi','adminarea/index.html','adminarea/admin.html',
'webadmin.cgi','webadmin/index.cgi','acceso.cgi','webadmin/admin.cgi','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.cgi','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.cgi','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.cgi','wp-login.cgi','adminLogin.cgi','admin/adminLogin.cgi','home.cgi','admin.cgi','adminarea/index.cgi',
'adminarea/admin.cgi','adminarea/login.cgi','panel-administracion/index.cgi','panel-administracion/admin.cgi','modelsearch/index.cgi',
'modelsearch/admin.cgi','admincontrol/login.cgi','adm/admloginuser.cgi','admloginuser.cgi','admin2.cgi','admin2/login.cgi','admin2/index.cgi','usuarios/login.cgi',
'adm/index.cgi','adm.cgi','affiliate.cgi','adm_auth.cgi','memberadmin.cgi','administratorlogin.cgi','admin_area/admin.brf','admin_area/login.brf','siteadmin/login.brf','siteadmin/index.brf','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.brf','bb-admin/index.brf','bb-admin/login.brf','bb-admin/admin.brf','admin/home.brf','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.brf','admin.brf','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.brf','cp.brf','administrator/index.brf','administrator/login.brf','nsw/admin/login.brf','webadmin/login.brfbrf','admin/admin_login.brf','admin_login.brf',
'administrator/account.brf','administrator.brf','acceso.brf','admin_area/admin.html','pages/admin/admin-login.brf','admin/admin-login.brf','admin-login.brf',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.brf','modelsearch/login.brf','moderator.brf','moderator/login.brf',
'moderator/admin.brf','account.brf','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.brf','admincontrol.brf',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.brf','adminarea/index.html','adminarea/admin.html',
'webadmin.brf','webadmin/index.brf','webadmin/admin.brf','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.brf','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.brf','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.brf','wp-login.brf','adminLogin.brf','admin/adminLogin.brf','home.brf','admin.brf','adminarea/index.brf',
'adminarea/admin.brf','adminarea/login.brf','panel-administracion/index.brf','panel-administracion/admin.brf','modelsearch/index.brf',
'modelsearch/admin.brf','admincontrol/login.brf','adm/admloginuser.brf','admloginuser.brf','admin2.brf','admin2/login.brf','admin2/index.brf','usuarios/login.brf',
'adm/index.brf','adm.brf','affiliate.brf','adm_auth.brf','memberadmin.brf','administratorlogin.brf','cpanel','cpanel.php','cpanel.html',)


    # Define a function to check a directory
    dynamic_directories = set(directories)

    directory_count_label = ctk.CTkLabel(root, text='Directories loaded: 0', padx=5)
    directory_count_label.place(relx=0.5, rely=0.45, anchor='center')

    def update_directory_count():
        directory_count_label.configure(text=f"Directories loaded: {len(dynamic_directories)}")

    update_directory_count()

    target_base = {'url': ''}

    def normalize_directory(value: str) -> str:
        value = value.strip()
        if not value:
            return ''
        if not value.endswith('/') and '.' not in value.split('/')[-1]:
            value = f"{value}/"
        return value

    def check_directory(directory):
        base = target_base['url'] or url_entry.get().strip()
        if not base:
            return
        full_url = base.rstrip('/') + '/' + directory.lstrip('/')
        if not is_url_in_scope(full_url):
            return
        try:
            # Make a request to the URL
            response = requests.get(full_url, allow_redirects=True, timeout=REQUEST_TIMEOUT)
            # If the status code is 200 and the page is not a 404 page
            if response.status_code == 200 and '404' not in response.text:
                # Insert the URL into the listbox
                listbox.insert(ctk.END, full_url)
        except:
            pass

    # Define a function to check all directories
    def check_directories():
        # Update the status label to indicate that the program is running
        status_label.configure(text='Working on it...')
        # Hide the listbox while the program is running
        threads = []
        # Create a thread for each directory
        for directory in list(dynamic_directories):
            t = threading.Thread(target=check_directory, args=(directory,))
            threads.append(t)
            t.start()

        # Define a function to periodically check if all threads have completed
        def check_threads():
            if all(not t.is_alive() for t in threads):
                # Update the status label to indicate that the program has finished running
                status_label.configure(text='Finished!')
            else:
                root.after(100, check_threads)

        # Start checking threads
        check_threads()

    # Define a function to start the program
    def start_program():
        base = url_entry.get().strip()
        if not base:
            messagebox.showerror('Missing URL', 'Enter a base URL to scan.')
            return
        if not base.startswith(('http://', 'https://')):
            base = 'http://' + base
        if not is_url_in_scope(base):
            messagebox.showerror('Scope Restriction', scope_error(base))
            return
        set_target(base)
        scope_label.configure(text=describe_scope())
        target_base['url'] = base.rstrip('/')
        url_entry.delete(0, tk.END)
        url_entry.insert(0, base)
        listbox.delete(0, ctk.END)
        check_directories()

    # Create a button to start the program
    button = ctk.CTkButton(root, text='Start', command=start_program)
    button.place(relx=0.7, rely=0.32, anchor='center')
    # Create a function to save the results to a file
    def save_results():
        # Prompt the user to choose a file location and name
        filename = asksaveasfilename(defaultextension='.txt')
        if filename:
            # Write the URLs to the file
            with open(filename, 'w') as f:
                for i in range(listbox.size()):
                    f.write(listbox.get(i) + '\n')

    # Create a button to save the results to a file
    save_button = ctk.CTkButton(root, text='Save Results', command=save_results)
    save_button.place(relx=0.5, rely=0.5, anchor='center')
    # Create a button to exit the program
    def exit_program():
        # Prompt the user to confirm that they want to exit
        if messagebox.askokcancel('Exit', 'Are you sure you want to exit?'):
            root.destroy()
    # Create a button to exit the program
    exit_button = ctk.CTkButton(root, text='Exit', command=exit_program)
    exit_button.place(relx=0.3, rely=0.5, anchor='center')

    # Create a function to upload a file for checking the directories in the file
    def upload_file():
        # Prompt the user to choose a file
        file_path = filedialog.askopenfilename()
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            # Get the directories from the file
            new_directories = [normalize_directory(line) for line in file.read().splitlines() if line.strip()]
            dynamic_directories.update(filter(None, new_directories))
            update_directory_count()
        url = url_entry.get()
        if url:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url.strip()
                url_entry.delete(0, tk.END)
                url_entry.insert(0, url)
            if not is_url_in_scope(url):
                messagebox.showerror('Scope Restriction', scope_error(url))
                return
            set_target(url)
            scope_label.configure(text=describe_scope())
            target_base['url'] = url.rstrip('/')
            check_directories()

    def fetch_wayback_dirs():
        base_url = url_entry.get().strip()
        if not base_url:
            messagebox.showerror('Missing URL', 'Enter a target URL before importing Wayback paths.')
            return
        if not is_url_in_scope(base_url):
            messagebox.showerror('Scope Restriction', scope_error(base_url))
            return
        parsed = urlsplit(base_url)
        domain = parsed.netloc or parsed.path
        status_label.configure(text='Querying Wayback Machine...')
        root.update_idletasks()
        try:
            response = requests.get(
                'https://web.archive.org/cdx/search/cdx',
                params={
                    'url': f'{domain}/*',
                    'output': 'json',
                    'fl': 'original',
                    'collapse': 'urlkey',
                    'limit': 2000,
                },
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            messagebox.showerror('Wayback Error', f'Failed to query Wayback Machine: {exc}')
            status_label.configure(text='Idle')
            return
        except ValueError:
            messagebox.showerror('Wayback Error', 'Wayback Machine returned invalid JSON.')
            status_label.configure(text='Idle')
            return

        discovered = set()
        for entry in data[1:]:
            archived_url = entry[0]
            path = urlsplit(archived_url).path
            path = path.strip('/')
            if not path:
                continue
            segments = path.split('/')
            for depth in range(1, min(len(segments) + 1, 4)):
                candidate = '/'.join(segments[:depth])
                normalized = normalize_directory(candidate)
                if normalized:
                    discovered.add(normalized)

        if not discovered:
            messagebox.showinfo('Wayback Result', 'No directories were discovered from the Wayback data.')
        else:
            before = len(dynamic_directories)
            dynamic_directories.update(discovered)
            added = len(dynamic_directories) - before
            update_directory_count()
            messagebox.showinfo('Wayback Result', f'Imported {added} directories from Wayback Machine results.')
        status_label.configure(text='Idle')

    # Create a button to upload a file
    upload_button = ctk.CTkButton(root, text='Upload File', command=upload_file)
    upload_button.place(relx=0.7, rely=0.5, anchor='center')

    wayback_button = ctk.CTkButton(root, text='Import Wayback Paths', command=fetch_wayback_dirs)
    wayback_button.place(relx=0.7, rely=0.55, anchor='center')

    # Override the default protocol for closing the window to show a confirmation prompt
    def on_closing():
        if messagebox.askokcancel('Exit', 'Are you sure you want to exit?'):
            root.destroy()
    # Set the protocol for closing the window
    root.protocol('WM_DELETE_WINDOW', on_closing)
    # Set minimum size and center window on screen
    root.minsize(400, 200)

    # Start the GUI loop
    root.mainloop()
