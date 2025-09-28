import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import threading
import re

banner = pyfiglet.figlet_format("Santana Scanner\ncreated by\ntitosantana00")
print(banner)

class SubdomainReconGUI:
    def __init__(self, master):
        self.master = master
        master.title("Subdomain Reconnaissance Tool")
        master.geometry("900x700") # Slightly larger window
        master.resizable(True, True) # Allow resizing

        # Configure grid weights for responsive layout
        master.grid_rowconfigure(2, weight=1) # Output frame row
        master.grid_columnconfigure(0, weight=1)

        self.create_widgets()
        self.check_dependencies()

    def create_widgets(self):
        # Main Input Frame (for Domain and URL)
        main_input_frame = ttk.Frame(self.master, padding="10")
        main_input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_input_frame.columnconfigure(1, weight=1)

        # Domain Recon Section
        domain_recon_frame = ttk.LabelFrame(main_input_frame, text="Subdomain Enumeration (Amass, Subfinder, crt.sh)", padding="10")
        domain_recon_frame.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        domain_recon_frame.columnconfigure(1, weight=1)

        ttk.Label(domain_recon_frame, text="Enter Domain:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.domain_entry = ttk.Entry(domain_recon_frame, width=50)
        self.domain_entry.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        self.domain_entry.bind("<Return>", lambda event: self.start_domain_recon()) # Bind Enter key

        self.start_domain_button = ttk.Button(domain_recon_frame, text="Start Domain Recon", command=self.start_domain_recon)
        self.start_domain_button.grid(row=0, column=2, padx=5, pady=5, sticky=tk.E)

        # GAU & XSS Recon Section
        gau_xss_recon_frame = ttk.LabelFrame(main_input_frame, text="URL & XSS Recon (GAU, Gf-XSS, Uro)", padding="10")
        gau_xss_recon_frame.grid(row=1, column=0, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        gau_xss_recon_frame.columnconfigure(1, weight=1)

        ttk.Label(gau_xss_recon_frame, text="Enter URL:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.url_entry = ttk.Entry(gau_xss_recon_frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        self.url_entry.bind("<Return>", lambda event: self.start_gau_xss_recon()) # Bind Enter key

        self.start_gau_xss_button = ttk.Button(gau_xss_recon_frame, text="Start URL/XSS Recon", command=self.start_gau_xss_recon)
        self.start_gau_xss_button.grid(row=0, column=2, padx=5, pady=5, sticky=tk.E)

        # Output Frame
        output_frame = ttk.Frame(self.master, padding="10")
        output_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S)) # Changed row to 1
        output_frame.rowconfigure(0, weight=1)
        output_frame.columnconfigure(0, weight=1)

        ttk.Label(output_frame, text="Reconnaissance Output:").grid(row=0, column=0, sticky=tk.W)
        self.output_text = tk.Text(output_frame, wrap=tk.WORD, state='disabled', width=80, height=20,
                                   font=("Courier New", 10), bg="#f0f0f0", fg="#333333",
                                   relief=tk.FLAT, bd=0) # Flat look
        self.output_text.grid(row=1, column=0, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Scrollbar for output text
        scrollbar = ttk.Scrollbar(output_frame, command=self.output_text.yview)
        scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S, tk.W))
        self.output_text['yscrollcommand'] = scrollbar.set

        # Control Frame (for save and clear buttons)
        control_frame = ttk.Frame(self.master, padding="10")
        control_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S)) # Changed row to 2
        control_frame.columnconfigure(0, weight=1) # Push buttons to the right
        control_frame.columnconfigure(1, weight=1)

        self.save_button = ttk.Button(control_frame, text="Save Current Output", command=self.save_current_output_gui)
        self.save_button.grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)

        self.clear_button = ttk.Button(control_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        # Status Bar
        self.status_label = ttk.Label(self.master, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.S)) # Changed row to 3

    def update_status(self, message):
        """Updates the status bar with a message."""
        self.status_label.config(text=message)
        self.master.update_idletasks() # Force GUI update

    def append_output(self, text):
        """Appends text to the output text area."""
        self.output_text.config(state='normal')
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END) # Scroll to the end
        self.output_text.config(state='disabled')
        self.master.update_idletasks()

    def clear_output(self):
        """Clears the output text area."""
        self.output_text.config(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state='disabled')
        self.update_status("Output cleared.")

    def check_tool_installed(self, tool_name, check_version_flag='--version'):
        """Checks if a command-line tool is installed, including custom paths for some tools."""
        # Custom paths for specific tools
        custom_paths = {
            "amass": "/usr/bin/amass",
            "subfinder": "/usr/bin/subfinder",
            "uro": "/home/titosantana00/.local/bin/uro"
        }
        tool_path = tool_name
        if tool_name in custom_paths:
            tool_path = custom_paths[tool_name]
        try:
            subprocess.run([tool_path, check_version_flag], capture_output=True, check=True, timeout=5)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            try:
                subprocess.run([tool_path], capture_output=True, check=True, timeout=5)
                return True
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                return False

    def get_tool_path(self, tool_name):
        """Returns the full path for a tool if a custom path is set, else just the tool name."""
        custom_paths = {
            "amass": "/usr/bin/amass",
            "subfinder": "/usr/bin/subfinder",
            "uro": "/home/titosantana00/.local/bin/uro"
        }
        return custom_paths.get(tool_name, tool_name)

    def check_dependencies(self):
        """Checks if all required tools are installed. Attempts to install missing ones."""
        required_tools = {
            "amass": {"url": "https://github.com/owasp-amass/amass", "install": "brew install amass"},
            "subfinder": {"url": "https://github.com/projectdiscovery/subfinder", "install": "brew install subfinder"},
            "curl": {"url": "https://curl.se/download.html", "install": "brew install curl"},
            "grep": {"url": "https://www.gnu.org/software/grep/", "install": "brew install grep"},
            "awk": {"url": "https://www.gnu.org/software/gawk/", "install": "brew install gawk"},
            "gau": {"url": "https://github.com/lc/gau", "install": "go install github.com/lc/gau/v2/cmd/gau@latest"},
            "gf": {"url": "https://github.com/tomnomnom/gf", "install": "go install github.com/tomnomnom/gf@latest"},
            "uro": {"url": "https://github.com/s0md3v/uro", "install": "pip3 install uro"}
        }
        missing_tools = []
        install_commands = []
        for tool, info in required_tools.items():
            # Use get_tool_path to check custom locations
            if not self.check_tool_installed(tool):
                # If the tool is found at a custom path, don't flag as missing
                tool_path = self.get_tool_path(tool)
                if os.path.exists(tool_path) and os.access(tool_path, os.X_OK):
                    continue
                missing_tools.append(f"{tool} (Download from: {info['url']})")
                install_commands.append((tool, info["install"]))

        if missing_tools:
            msg = (
                "The following tools are not found in your system's PATH.\n\n" +
                "\n".join(missing_tools) +
                "\n\nWould you like to attempt automatic installation?"
            )
            if messagebox.askyesno("Missing Dependencies", msg):
                for tool, cmd in install_commands:
                    self.update_status(f"Installing {tool}...")
                    self.append_output(f"\nAttempting to install {tool} using: {cmd}\n")
                    try:
                        if tool in ["gau", "gf"]:
                            # Ensure Go bin is in PATH after install
                            process = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
                            go_path = os.path.expanduser("~/go/bin")
                            if go_path not in os.environ.get("PATH", ""):
                                os.environ["PATH"] = go_path + os.pathsep + os.environ.get("PATH", "")
                        else:
                            process = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
                        if process.returncode != 0:
                            self.append_output(f"Install error for {tool}: {process.stderr}\n")
                        else:
                            self.append_output(f"{tool} installed successfully.\n")
                    except Exception as e:
                        self.append_output(f"Exception during install of {tool}: {e}\n")
                # Re-check after install attempts
                still_missing = []
                for tool, info in required_tools.items():
                    if not self.check_tool_installed(tool):
                        still_missing.append(tool)
                if still_missing:
                    messagebox.showwarning(
                        "Dependencies Not Fully Installed",
                        "Some tools could not be installed automatically. Please install them manually: " + ", ".join(still_missing)
                    )
                    self.start_domain_button.config(state=tk.DISABLED)
                    self.start_gau_xss_button.config(state=tk.DISABLED)
                    self.update_status("Missing dependencies. Please install required tools.")
                    return False
                else:
                    self.start_domain_button.config(state=tk.NORMAL)
                    self.start_gau_xss_button.config(state=tk.NORMAL)
                    self.update_status("All dependencies installed.")
                    return True
            else:
                messagebox.showwarning(
                    "Missing Dependencies",
                    "The following tools are not found in your system's PATH. "
                    "Please install them for full functionality:\n\n" + "\n".join(missing_tools)
                )
                self.start_domain_button.config(state=tk.DISABLED)
                self.start_gau_xss_button.config(state=tk.DISABLED)
                self.update_status("Missing dependencies. Please install required tools.")
                return False
        return True

    def start_domain_recon(self):
        """Starts the domain reconnaissance process in a separate thread."""
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("Input Error", "Please enter a domain.")
            return

        # Simple domain validation
        if not re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', domain):
            messagebox.showwarning("Input Error", "Please enter a valid domain (e.g., example.com).")
            return

        if not self.check_dependencies(): # Re-check before starting
            return

        self.start_domain_button.config(state=tk.DISABLED)
        self.start_gau_xss_button.config(state=tk.DISABLED) # Disable other button
        self.clear_output()
        self.append_output(f"--- Starting Subdomain Enumeration for {domain} ---\n\n")
        self.update_status(f"Starting subdomain reconnaissance for {domain}...")

        # Run the recon process in a separate thread to keep the GUI responsive
        recon_thread = threading.Thread(target=self.run_domain_recon_process, args=(domain,))
        recon_thread.daemon = True # Allow the thread to exit with the main program
        recon_thread.start()

    def run_domain_recon_process(self, domain):
        """Executes the subdomain enumeration tools and combines results."""
        temp_files = ["amass_output.txt", "subfinder_output.txt", "crtsh_output.txt"]
        try:
            # Clean up previous temporary files
            for file in temp_files:
                if os.path.exists(file):
                    os.remove(file)

            # Run Amass
            self.update_status(f"Running Amass for {domain}...")
            self.get_subdomains_amass(domain)

            # Run Subfinder
            self.update_status(f"Running Subfinder for {domain}...")
            self.get_subdomains_subfinder(domain)

            # Run crt.sh via curl (Note: This is brittle and relies on system tools)
            self.update_status(f"Running crt.sh for {domain}...")
            self.get_subdomains_crtsh(domain)

            # Combine results
            self.update_status("Combining subdomains...")
            combined_subdomains = self.combine_subdomains()

            if combined_subdomains:
                self.append_output(f"\n--- Found {len(combined_subdomains)} unique subdomains for {domain} ---\n")
                for subdomain in sorted(list(combined_subdomains)):
                    self.append_output(subdomain + "\n")
                self.update_status(f"Subdomain reconnaissance complete. Found {len(combined_subdomains)} subdomains.")
            else:
                self.append_output("\nNo subdomains found or tools did not produce output.\n")
                self.update_status("Subdomain reconnaissance complete. No subdomains found.")

        except Exception as e:
            self.update_status(f"An error occurred during domain recon: {e}")
            self.append_output(f"Error during domain reconnaissance: {e}\n")
        finally:
            # Clean up temporary files
            for file in temp_files:
                if os.path.exists(file):
                    try:
                        os.remove(file)
                    except OSError as e:
                        print(f"Error removing temporary file {file}: {e}")
            self.start_domain_button.config(state=tk.NORMAL) # Re-enable button
            self.start_gau_xss_button.config(state=tk.NORMAL) # Re-enable other button

    def get_subdomains_amass(self, domain):
        """Runs Amass and saves output to a file."""
        try:
            amass_path = self.get_tool_path("amass")
            command = [amass_path, "enum", "-d", domain, "-o", "amass_output.txt", "-silent"]
            process = subprocess.run(command, capture_output=True, text=True, check=False)
            if process.returncode != 0 and process.stderr:
                self.append_output(f"Amass error (exit code {process.returncode}): {process.stderr}\n")
        except Exception as e:
            self.append_output(f"Error running Amass: {e}\n")

    def get_subdomains_subfinder(self, domain):
        """Runs Subfinder and saves output to a file."""
        try:
            subfinder_path = self.get_tool_path("subfinder")
            command = [subfinder_path, "-d", domain, "-o", "subfinder_output.txt", "-silent"]
            process = subprocess.run(command, capture_output=True, text=True, check=False)
            if process.returncode != 0 and process.stderr:
                self.append_output(f"Subfinder error (exit code {process.returncode}): {process.stderr}\n")
        except Exception as e:
            self.append_output(f"Error running Subfinder: {e}\n")

    def get_subdomains_crtsh(self, domain):
        """Fetches subdomains from crt.sh using curl, grep, and awk."""
        # Note: This command relies on specific HTML structure of crt.sh and system tools.
        try:
            # The command uses shell pipes, so shell=True is necessary
            command = f"curl -s https://crt.sh/?q={domain} | grep 'TD;' | awk -F 'TD' '{{print $3}}' > crtsh_output.txt"
            process = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)
            if process.returncode != 0 and process.stderr:
                self.append_output(f"crt.sh (curl/grep/awk) error (exit code {process.returncode}): {process.stderr}\n")
        except Exception as e:
            self.append_output(f"Error running crt.sh command: {e}\n")

    def combine_subdomains(self):
        """Combines subdomains from all output files."""
        files = ["amass_output.txt", "subfinder_output.txt", "crtsh_output.txt"]
        subdomains = set()
        for file in files:
            if os.path.exists(file):
                try:
                    with open(file, "r") as f:
                        for line in f:
                            # Basic cleaning for crt.sh output if it contains HTML/whitespace
                            clean_line = line.strip()
                            if clean_line:
                                # Further refine for crt.sh output that might include HTML tags
                                clean_line = re.sub(r'<[^>]+>|<\/A>$|^>', '', clean_line).strip()
                                if clean_line: # Check again after cleaning
                                    subdomains.add(clean_line)
                except Exception as e:
                    self.append_output(f"Error reading {file}: {e}\n")
        return subdomains

    def start_gau_xss_recon(self):
        """Starts the GAU and XSS recon process in a separate thread."""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return

        if not self.check_dependencies(): # Re-check before starting
            return

        self.start_gau_xss_button.config(state=tk.DISABLED)
        self.start_domain_button.config(state=tk.DISABLED) # Disable other button
        self.clear_output()
        self.append_output(f"--- Starting URL & XSS Recon for {url} ---\n\n")
        self.update_status(f"Starting URL & XSS reconnaissance for {url}...")

        gau_xss_thread = threading.Thread(target=self.run_gau_xss_process, args=(url,))
        gau_xss_thread.daemon = True
        gau_xss_thread.start()

    def run_gau_xss_process(self, url):
        """Executes GAU, gf xss, and uro commands."""
        # Generate base filename from URL
        base_filename = re.sub(r'https?://', '', url)
        base_filename = re.sub(r'[^a-zA-Z0-9]', '_', base_filename)
        gau_output_file = f"{base_filename}_gau.txt"
        xss_output_file = f"{base_filename}_xss.txt"

        try:
            # Clean up previous temporary files
            if os.path.exists(gau_output_file):
                os.remove(gau_output_file)
            if os.path.exists(xss_output_file):
                os.remove(xss_output_file)

            # Run GAU
            self.update_status(f"Running GAU for {url}...")
            self.append_output(f"Executing: echo {url} | gau --o {gau_output_file}\n")
            gau_path = self.get_tool_path("gau")
            gau_command = f"echo {url} | {gau_path} --o {gau_output_file}"
            process = subprocess.run(gau_command, shell=True, capture_output=True, text=True, check=False)
            if process.returncode != 0 and process.stderr:
                self.append_output(f"GAU error (exit code {process.returncode}): {process.stderr}\n")
            else:
                self.append_output(f"GAU command executed. Results saved to {gau_output_file}\n")

            # Run gf xss | uro
            self.update_status(f"Filtering for potential XSS vulnerabilities...")
            uro_path = self.get_tool_path("uro")
            self.append_output(f"Executing: cat {gau_output_file} | gf xss | {uro_path} | tee {xss_output_file}\n")
            xss_command = f"cat {gau_output_file} | gf xss | {uro_path} | tee {xss_output_file}"
            process = subprocess.run(xss_command, shell=True, capture_output=True, text=True, check=False)
            if process.returncode != 0 and process.stderr:
                self.append_output(f"XSS filtering error (exit code {process.returncode}): {process.stderr}\n")
            else:
                self.append_output(f"Filtered potential XSS results saved to {xss_output_file}\n")

            # Display results in GUI (Displaying final XSS results is most relevant)
            if os.path.exists(xss_output_file):
                with open(xss_output_file, 'r') as f:
                    xss_results = f.read().strip()
                if xss_results:
                    self.append_output(f"\n--- Potential XSS Results ({xss_output_file}) ---\n")
                    self.append_output(xss_results + "\n")
                else:
                    self.append_output(f"\nNo potential XSS results found in {xss_output_file}.\n")

            self.update_status(f"URL & XSS reconnaissance complete for {url}.")

        except Exception as e:
            self.update_status(f"An error occurred during URL/XSS recon: {e}")
            self.append_output(f"Error during URL/XSS reconnaissance: {e}\n")
        finally:
            # Re-enable buttons
            self.start_gau_xss_button.config(state=tk.NORMAL)
            self.start_domain_button.config(state=tk.NORMAL)

    def save_current_output_gui(self):
        """Prompts user to save the current content of the output text area to a file."""
        output_content = self.output_text.get(1.0, tk.END).strip()
        if not output_content:
            messagebox.showinfo("Save Info", "No output to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Current Output As"
        )
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(output_content)
                self.update_status(f"Output saved to {file_path}")
                messagebox.showinfo("Save Success", f"Current output successfully saved to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save file: {e}")
                self.update_status(f"Error saving file: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SubdomainReconGUI(root)
    root.mainloop()
