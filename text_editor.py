#!/usr/bin/env python3
import json
import os
from pathlib import Path

class FSocietyTextEditor:
    def __init__(self):
        self.config_file = "text_config.json"
        self.load_config()
    
    def load_config(self):
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print("text_config.json not found!")
            return False
        except json.JSONDecodeError:
            print("Invalid JSON in text_config.json!")
            return False
        return True
    
    def save_config(self):
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            print("Configuration saved successfully!")
            return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False
    
    def show_menu(self):
        print("\n" + "="*60)
        print("           FSOCIETY TEXT CONFIGURATION EDITOR")
        print("="*60)
        print("1. Edit Loading Messages")
        print("2. Edit Banner Text")
        print("3. Edit Help Text")
        print("4. Edit Startup Messages")
        print("5. Edit Command Responses")
        print("6. Edit Status Messages")
        print("7. Edit Exit Messages")
        print("8. Edit Error Messages")
        print("9. View All Configuration")
        print("0. Save and Exit")
        print("="*60)
    
    def edit_loading_messages(self):
        print("\nCurrent Loading Messages:")
        for i, msg in enumerate(self.config['loading_messages'], 1):
            print(f"{i:2d}. {msg}")
        
        print("\nOptions:")
        print("a - Add new message")
        print("e - Edit existing message")
        print("d - Delete message")
        print("r - Return to main menu")
        
        choice = input("\nEnter choice: ").lower().strip()
        
        if choice == 'a':
            new_msg = input("Enter new loading message: ").strip()
            if new_msg:
                self.config['loading_messages'].append(new_msg)
                print("Message added!")
        
        elif choice == 'e':
            try:
                idx = int(input("Enter message number to edit: ")) - 1
                if 0 <= idx < len(self.config['loading_messages']):
                    new_msg = input(f"Edit message: {self.config['loading_messages'][idx]}\nNew message: ").strip()
                    if new_msg:
                        self.config['loading_messages'][idx] = new_msg
                        print("Message updated!")
                else:
                    print("Invalid message number!")
            except ValueError:
                print("Invalid input!")
        
        elif choice == 'd':
            try:
                idx = int(input("Enter message number to delete: ")) - 1
                if 0 <= idx < len(self.config['loading_messages']):
                    deleted = self.config['loading_messages'].pop(idx)
                    print(f"Deleted: {deleted}")
                else:
                    print("Invalid message number!")
            except ValueError:
                print("Invalid input!")
    
    def edit_banner_text(self):
        print("\nBanner Configuration:")
        print("1. Terminal Title:", self.config['banners']['terminal_title'])
        print("2. Subtitle:", self.config['banners']['subtitle'])
        print("3. Main Banner (ASCII Art)")
        
        choice = input("\nEnter 1, 2, 3 or r to return: ").strip()
        
        if choice == '1':
            new_title = input("Enter new terminal title: ").strip()
            if new_title:
                self.config['banners']['terminal_title'] = new_title
                print("Terminal title updated!")
        
        elif choice == '2':
            new_subtitle = input("Enter new subtitle: ").strip()
            if new_subtitle:
                self.config['banners']['subtitle'] = new_subtitle
                print("Subtitle updated!")
        
        elif choice == '3':
            print("Current banner:")
            for i, line in enumerate(self.config['banners']['main_banner'], 1):
                print(f"{i:2d}. {line}")
            
            line_num = input("\nEnter line number to edit (or 'new' to add): ").strip()
            
            if line_num == 'new':
                new_line = input("Enter new banner line: ")
                self.config['banners']['main_banner'].append(new_line)
                print("New line added!")
            else:
                try:
                    idx = int(line_num) - 1
                    if 0 <= idx < len(self.config['banners']['main_banner']):
                        new_line = input(f"Edit line: {self.config['banners']['main_banner'][idx]}\nNew line: ")
                        self.config['banners']['main_banner'][idx] = new_line
                        print("Line updated!")
                    else:
                        print("Invalid line number!")
                except ValueError:
                    print("Invalid input!")
    
    def edit_command_responses(self):
        print("\nCommand Responses:")
        responses = self.config['command_responses']
        
        for i, (key, value) in enumerate(responses.items(), 1):
            print(f"{i:2d}. {key}: {value}")
        
        try:
            choice = int(input("\nEnter number to edit (0 to return): "))
            if choice == 0:
                return
            
            keys = list(responses.keys())
            if 1 <= choice <= len(keys):
                key = keys[choice - 1]
                new_value = input(f"Edit '{key}':\nCurrent: {responses[key]}\nNew: ").strip()
                if new_value:
                    responses[key] = new_value
                    print("Response updated!")
            else:
                print("Invalid choice!")
        except ValueError:
            print("Invalid input!")
    
    def edit_exit_messages(self):
        print("\nCurrent Exit Messages:")
        for i, msg in enumerate(self.config['exit_messages'], 1):
            print(f"{i:2d}. {msg}")
        
        print("\nOptions:")
        print("a - Add new message")
        print("e - Edit existing message")
        print("d - Delete message")
        print("r - Return to main menu")
        
        choice = input("\nEnter choice: ").lower().strip()
        
        if choice == 'a':
            new_msg = input("Enter new exit message: ").strip()
            if new_msg:
                self.config['exit_messages'].append(new_msg)
                print("Message added!")
        
        elif choice == 'e':
            try:
                idx = int(input("Enter message number to edit: ")) - 1
                if 0 <= idx < len(self.config['exit_messages']):
                    new_msg = input(f"Edit message: {self.config['exit_messages'][idx]}\nNew message: ").strip()
                    if new_msg:
                        self.config['exit_messages'][idx] = new_msg
                        print("Message updated!")
                else:
                    print("Invalid message number!")
            except ValueError:
                print("Invalid input!")
        
        elif choice == 'd':
            try:
                idx = int(input("Enter message number to delete: ")) - 1
                if 0 <= idx < len(self.config['exit_messages']):
                    deleted = self.config['exit_messages'].pop(idx)
                    print(f"Deleted: {deleted}")
                else:
                    print("Invalid message number!")
            except ValueError:
                print("Invalid input!")
    
    def view_all_config(self):
        print("\n" + "="*60)
        print("           COMPLETE CONFIGURATION")
        print("="*60)
        print(json.dumps(self.config, indent=2, ensure_ascii=False))
        print("="*60)
        input("\nPress Enter to continue...")
    
    def run(self):
        while True:
            self.show_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '1':
                self.edit_loading_messages()
            elif choice == '2':
                self.edit_banner_text()
            elif choice == '3':
                print("Help text editing - Coming soon!")
            elif choice == '4':
                print("Startup messages editing - Coming soon!")
            elif choice == '5':
                self.edit_command_responses()
            elif choice == '6':
                print("Status messages editing - Coming soon!")
            elif choice == '7':
                self.edit_exit_messages()
            elif choice == '8':
                print("Error messages editing - Coming soon!")
            elif choice == '9':
                self.view_all_config()
            elif choice == '0':
                if self.save_config():
                    print("Configuration saved. Exiting...")
                    break
            else:
                print("Invalid choice!")

if __name__ == "__main__":
    editor = FSocietyTextEditor()
    editor.run() 
