# Requirements to run code:
#   pip install cryptography
#   pip install prettytable

# importing the necessary libraries
import hashlib
import requests
from prettytable import PrettyTable
from cryptography.fernet import Fernet
import random


# Graphics to be used in the program
encryption_graphic = '''

██████╗░███╗░░██╗░█████╗░██████╗░██╗░░░██╗██████╗░███████╗░░███╗░░░█████╗░███╗░░██╗
╚════██╗████╗░██║██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚════██║░████║░░██╔══██╗████╗░██║
░█████╔╝██╔██╗██║██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░░██╔╝██╔██║░░██║░░██║██╔██╗██║
░╚═══██╗██║╚████║██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██╔╝░╚═╝██║░░██║░░██║██║╚████║
██████╔╝██║░╚███║╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░██╔╝░░███████╗╚█████╔╝██║░╚███║
╚═════╝░╚═╝░░╚══╝░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░╚═╝░░░╚══════╝░╚════╝░╚═╝░░╚══╝
\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\ CIA TrI4D \/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/

'''

decryption_graphic = '''


██████╗░██████╗░░█████╗░██████╗░██╗░░░██╗██████╗░███████╗░░███╗░░░█████╗░███╗░░██╗
██╔══██╗╚════██╗██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚════██║░████║░░██╔══██╗████╗░██║
██║░░██║░█████╔╝██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░░██╔╝██╔██║░░██║░░██║██╔██╗██║
██║░░██║░╚═══██╗██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██╔╝░╚═╝██║░░██║░░██║██║╚████║
██████╔╝██████╔╝╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░██╔╝░░███████╗╚█████╔╝██║░╚███║
╚═════╝░╚═════╝░░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░╚═╝░░░╚══════╝░╚════╝░╚═╝░░╚══╝
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/ H1D3 Y0Ur 5Cr33N \/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/

'''
generate_graphic = '''


░██████╗░██████╗░███╗░░██╗██████╗░██████╗░░░██╗██╗████████╗██████╗░
██╔════╝░╚════██╗████╗░██║╚════██╗██╔══██╗░██╔╝██║╚══██╔══╝╚════██╗
██║░░██╗░░█████╔╝██╔██╗██║░█████╔╝██████╔╝██╔╝░██║░░░██║░░░░█████╔╝
██║░░╚██╗░╚═══██╗██║╚████║░╚═══██╗██╔══██╗███████║░░░██║░░░░╚═══██╗
╚██████╔╝██████╔╝██║░╚███║██████╔╝██║░░██║╚════██║░░░██║░░░██████╔╝
░╚═════╝░╚═════╝░╚═╝░░╚══╝╚═════╝░╚═╝░░╚═╝░░░░░╚═╝░░░╚═╝░░░╚═════╝░
/\/\/\/\/\/\/\/\/\/\/ D0N7 Wr173 7H15 D0WN \/\/\/\/\/\/\/\/\/\/\/\/

'''

# Welcome message for the user with an appealing graphic
print("Welcome to!" + '''


░█████╗░██████╗░██╗░░░██╗██████╗░████████╗██╗░░██╗
██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝╚██╗██╔╝
██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░██║░░░░╚███╔╝░
██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░░██╔██╗░
╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░░██║░░░██╔╝╚██╗
░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░╚═╝░░╚═╝
\/Y0Ur 0N3 5T0P 5H0P F0r 411 Y0Ur P455W0rD N33D5\/

''')

# Main user input for the program. The whole code depends on this input
user_choice = input("Do you want to DECRYPT, ENCRYPT, or GENERATE a password (D/E/G): ")

# Main dictionary of the program where the data related to the password is stored like 
# the strength, if the password is compromised or not, etc.
# Each step in the program adds a key-value pair to this dictionary
# Which is later used to make a table using the PrettyTable module
# Problem solved- This enables for all values to be collected in one place
# and then used to make a table using the dict_to_prettytable() function
# In the future if we want to add more data to the table, we can just add a 
# key-value pair to this dictionary
main_password_data = {}

# This function makes a table using the PrettyTable module by taking in a dictionary as parameter
def dict_to_prettytable(data_dict):
    table = PrettyTable()

    # Convert non-list values to lists
    for key, value in data_dict.items():

        # Check if the value is not already a list
        if not isinstance(value, list): 
            # Convert the value to a list
            data_dict[key] = [value]

    # Get the length of the longest list in the dictionary
    max_length = max([len(value) for value in data_dict.values()])

    # Fill in missing values with empty strings
    for key, value in data_dict.items():

        # Check if the length of the list is less than the max length
        if len(value) < max_length:

            # Fill in the missing values with empty string to make it the same length as the longest list(max_lenght)
            data_dict[key] = value + [''] * (max_length - len(value))

    # Add the columns to the table
    for key, value in data_dict.items():
        table.add_column(key, value)

    return table

#@@@@@@@@@@ CheckStrength function @@@@@@@@@@
# Check the strength of the password
def CheckStrength(password):    # Implement main_password_data dictionary
    
        # Set the main_password_data dictionary as a global variable
        global main_password_data

        # all special characters
        SpecChar = "!@#$%^&*()_+{}|:<>?[]\;',./"
    
        # 0-9 numbers
        NUMBERS = "0123456789"
    
        # the alphabet
        ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
        # special character bool
        HasSpecChar = False
    
        # number bool
        HasNum = False
    
        # capital letter bool
        HasCapAlphabet = False
    
        # lowercase letter bool
        HasLowAlphabet = False
    
        # each letter in password loop
        for letter in password:

            if letter in SpecChar:
                
                # if special character is found, set HasSpecChar bool to true
                HasSpecChar = True

            elif letter in NUMBERS:
    
                # if number is found, set HasNum bool to true
                HasNum = True
    
            elif letter in ALPHABET:
                
                if letter == letter.upper():
                    
                    # if capital letter is found, set HasCapAlphabet bool to true
                    HasCapAlphabet = True
                else:
    
                    # else set HasLowAlphabet bool to true, since it can only be either lower or upper case
                    HasLowAlphabet = True

        # All possible conditions listed:
        # special character, number, capital letter, lowercase letter
            # Send the data to main_password_data dictionary meanwhile returning the strength
        if HasSpecChar and HasNum and HasCapAlphabet and HasLowAlphabet:
    
            main_password_data['Strength'] = "Strong"

            return("Strong")
    
        # special character, number, capital letter
        elif HasSpecChar and HasNum and HasCapAlphabet:
            
            main_password_data['Strength'] = "Medium"
            
            return("Medium")
        
        # special character, number, lowercase letter
        elif HasSpecChar and HasNum and HasLowAlphabet:
    
            main_password_data['Strength'] = "Medium"

            return("Medium")
        
        # special character, capital letter, lowercase letter
        elif HasSpecChar and HasCapAlphabet and HasLowAlphabet:

            main_password_data['Strength'] = "Medium"

            return("Medium")
        
        # number, capital letter, lowercase letter
        elif HasNum and HasCapAlphabet and HasLowAlphabet:

            main_password_data['Strength'] = "Medium"

            return("Medium")

        # special character and a number
        elif HasSpecChar and HasNum:

            main_password_data['Strength'] = "Weak"

            return("Weak")

        # special character and a capital letter
        elif HasSpecChar and HasCapAlphabet:

            main_password_data['Strength'] = "Weak"

            return("Weak")

        # special character and a lowercase letter
        elif HasSpecChar and HasLowAlphabet:

            main_password_data['Strength'] = "Weak"

            return("Weak")

        # number and a capital letter
        elif HasNum and HasCapAlphabet:

            main_password_data['Strength'] = "Weak"

            return("Weak")

        # number and a lowercase letter
        elif HasNum and HasLowAlphabet:

            main_password_data['Strength'] = "Weak"

            return("Weak")

        # capital letter and a lowercase letter
        elif HasCapAlphabet and HasLowAlphabet:

            main_password_data['Strength'] = "Weak"

            return("Weak")

        #special character
        elif HasSpecChar:

            main_password_data['Strength'] = "Very Weak"

            return("Very Weak")

        # number
        elif HasNum:
                
            main_password_data['Strength'] = "Very Weak"

            return("Very Weak")

        # capital letter
        elif HasCapAlphabet:

            main_password_data['Strength'] = "Very Weak"

            return("Very Weak")
        
        # lowercase letter
        elif HasLowAlphabet:

            main_password_data['Strength'] = "Very Weak"

            return("Very Weak")

        else:

            # This is mainly for the case when the password is empty
            main_password_data['Strength'] = "N/A"

            return("N/A")

#@@@@@@@@@@ Cryptography library 'Fernet' Encryption @@@@@@@@@@
def encrypt_crypto(password):

    # Set the main_password_data dictionary as a global variable
    global main_password_data

    # Import fernet from the cryptography library
    from cryptography.fernet import Fernet

    # Generate a key
    key = Fernet.generate_key()

    # Create a cipher_suite object, this can be used to encrypt and decrypt, 
    # eg0: cipher_suite.encrypt(b"Hello World")
    cipher_suite = Fernet(key)

    # Encrypt the password after encoding it and passing it to 'cipher_suite" 
    cipher_text =  cipher_suite.encrypt(password.encode())

    # Decrypt the password, this is just for testing purposes
    #   This variable (original_text) is not used anywhere.
    original_text = cipher_suite.decrypt(cipher_text)

    # Add the encrypted password and the key to the global main_password_data dictionary
    main_password_data['encrypted_password'] = cipher_text.decode('utf-8')
    main_password_data['key'] = key.decode('utf-8')

    # Return the encrypted password and the key in 'utf-8' format for better readability
    return cipher_text.decode('utf-8'), key.decode('utf-8')

#@@@@@@@@@@ ROTn ENCRYPTIONS @@@@@@@@@@
# ROT 13 encryption
def rot13(password):
    
        # Create an empty string, whcih will be used to store the encrypted password
        enc = ""

        # List of Alphabets which would be used to match the index of the letters in the password
        ALPHABET = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']

        # List of ROT13 Alphabets which woule be used to match the index of the letters in the password, 
        # and send the letters to the 'enc' string.
        ROT13_ALPHABET = ['n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M']
    
        # Loop through every letter in the password
        for letter in password:
            
            # Check if the letter is in the ALPHABET list
            if letter in ALPHABET:
    
                # Get the index of the letter in the ALPHABET list
                index = ALPHABET.index(letter)
    
                # Add the letter from the 'index' above to the 'enc' string
                enc += ROT13_ALPHABET[index]

            else:
                # If the letter is not in the ALPHABET list, then just add the letter to the 'enc' string without
                # going through the process of rot13
                enc += letter

        # Return the encrypted password 
        return enc

# ROT 47 encryption
def rot47(password, function):

    if function == "encrypt":
        # Create an empty string, whcih will be used to store the encrypted password
        enc = ""

        # List of Alphabets which would be used to match the index of the letters in the password
        ALPHABET = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',\
                    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',\
                        'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '@', '#', '$',\
                            '%', '^', '&', '*', '(', ')', '_', '+', '~', '`', '|', '}', '{', '[', ']', '\\', ':', ';', '?', '>', '<',\
                                ',', '.', '/', '-', '=']
    
        # List of ROT47 Alphabets whcih would be used to match the index of the letters in the password, and send the letters
        #  to the 'enc' string later in the code
        ROT47_ALPHABET = ['p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', '!', '"', '#', '$', '%', '&',\
                        "'", '(', ')', '*', '+', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A',\
                            'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'P',\
                                'o', 'R', 'S', 'T', '/', 'U', 'Y', 'W', 'X', '0', 'Z', 'O', '1', 'M', 'N', 'L', ',', '.', '-', 'i',\
                                    'j', 'n', 'm', 'k', '[', ']', '^', '\\', 'l']

        # Loop through every letter in the password, same as the rot13 function previously in the code
        for letter in password:

            # Check if the letter is in the ALPHABET list
            if letter in ALPHABET:

                # Get the index of the letter in the ALPHABET list
                index = ALPHABET.index(letter)

                # Add the letter from the index variable above to the enc string
                enc += ROT47_ALPHABET[index]

            else:
                # If the letter is not in the ALPHABET list, then just add the letter to the 'enc' string without
                # going through the process of rot47

                enc += letter

        # Return the encrypted password
               # Return the encrypted password
        return enc
    
    elif function == "decrypt":
        # Create an empty string, which will be used to store the decrypted password
        dec = ""

        # List of ROT47 Alphabets which would be used to match the index of the letters in the encrypted password
        ROT47_ALPHABET = ['p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', '!', '"', '#', '$', '%', '&', \
                          "'", '(', ')', '*', '+', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', \
                          'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'P', \
                          'o', 'R', 'S', 'T', '/', 'U', 'Y', 'W', 'X', '0', 'Z', 'O', '1', 'M', 'N', 'L', ',', '.', '-', 'i', \
                          'j', 'n', 'm', 'k', '[', ']', '^', '\\', 'l']

        # List of Alphabets which would be used to match the index of the letters in the encrypted password
        ALPHABET = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', \
                    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', \
                    'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '@', '#', '$', \
                    '%', '^', '&', '*', '(', ')', '_', '+', '~', '`', '|', '}', '{', '[', ']', '\\', ':', ';', '?', '>', '<', \
                    ',', '.', '/', '-', '=']

        # Loop through every letter in the password, same as the encryption
        for letter in password:

            # Check if the letter is in the ROT47_ALPHABET list
            if letter in ROT47_ALPHABET:

                # Get the index of the letter in the ROT47_ALPHABET list
                index = ROT47_ALPHABET.index(letter)

                # Add the letter from the index variable above to the dec string
                dec += ALPHABET[index]

            else:
                # If the letter is not in the ROT47_ALPHABET list, then just add the letter to the 'dec' string without
                # going through the process of rot47

                dec += letter

        # Return the decrypted password
        return dec

# Have I Been Pwned API
# API Author: Troy Hunt
# API Version: 3.0
# API Documentation: https://haveibeenpwned.com/API/v3
# API Usage: This API is used to check if passwords have been compromised in data breaches.

#@@@@@@@@@@ Haveibeenpwned API function @@@@@@@@@@
# Will be used to check if the password was in a compromised database or not
def pwned_api(password):

    # Set main_password_data as a global variable
    global main_password_data

    # Make the password in sha1 format using hashlib, then convert it to uppercase
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # Split the hash into the first 5 characters and the rest
    # The first 5 characters are assigned to prefix and the rest to suffix as per the requirements of the API
    prefix = sha1_password[:5]

    suffix = sha1_password[5:]

    # Create the URL var to send the request to
    url = 'https://api.pwnedpasswords.com/range/' + prefix

    # Get the returned data from the API using the requests.get function from the requests library
    # and store that data in the returned_data variable
    returned_data = requests.get(url)
    
    # Split the returned data into a list of hashes
    hashes = (line.split(':') for line in returned_data.text.splitlines())

    # Check if the suffix is in the returned list of hashes
    count = next((int(count) for t, count in hashes if t == suffix), 0)

    # Set the compromised variable to No/Yes depending on the number of times the password was compromised
    if count == 0:
        compromised = "No"
    else:
        compromised = "Yes"

    # Return whether the password is compromised and the number of times it has been compromised
    return compromised, count

#Function which combines all the encryption functions for the ULTIMATE ENCRYPTION!
def main(user_choice):

    # if the user chooses to encrypt a password
    if user_choice == "E":

        # Set main_password_data as a global variable
        global main_password_data

        # Print encryption graphic to the screen
        print(encryption_graphic)

        # Get the user's password to encrypt
        user_input_password = input("Enter a password: ")

        # Encrypt the password using the rot13, rot47 and fernet encryption functions previopusly made
        rot13_encrypted_password = rot13(user_input_password)
        rot47_encrypted_password = rot47(rot13_encrypted_password, "encrypt")
        crypto_encrypted_password = encrypt_crypto(rot47_encrypted_password)

        # Get the strength of the password using the CheckStrength function
        #  This also adds the strength of the password to the main_password_data dictionary
        #     which is already in the CheckStrength function
        strength_of_password = CheckStrength(user_input_password)

        # The final password is the fernet encrypted password
        final_encrypted_password = crypto_encrypted_password

        # Set crypto_key to the key returned by the encrypt_crypto function for future use
        crypto_key = crypto_encrypted_password[1]

        # Check if the password has been compromsied or not, and return the result in two 
        # variables since the function returns a tuple
        pwned_compromised, pwned_count = pwned_api(user_input_password)

        # Add the encrypted password and the key to the main_password_data dictionary
        # depending on if the password is compromised or not.
        if pwned_count == 0:
            main_password_data["Compromised"] = [str(pwned_compromised)]
        else:
            main_password_data["Compromised"] = [str(pwned_compromised) + " " + str(pwned_count) + " Times"]

        # Use the dictionary to prettytable function to convert the dictionary to a prettytable
        table = dict_to_prettytable(main_password_data)
        # Print the table to the screen
        print(table)
    
    # If the user wants to decrypt a password
    elif user_choice == "D":
        
        #Get the encrypted password and the key from the user
        encrypted_password = input("Enter the encrypted password: ")
        key = input("Enter the key: ")

        # Decrypt the password step by step
        # First Fernet, then ROT 47, then ROT 13
        
        k = Fernet(key)

        #Decrypt Fernet encrypted password
        fernet_decrypted_password = k.decrypt(encrypted_password).decode("utf-8")

        #Decrypt ROT 47 encrypted password, the same function can be used to decrypt ROT 47
        rot47_decrypted_password = rot47(fernet_decrypted_password, "decrypt")

        #Decrypt ROT 13 encrypted password, the same functioncan be used to decrypt ROT 13
        rot13_decrypted_password = rot13(rot47_decrypted_password)

        # Print the decrypted password to the screen
        print("Original Password: " + str(rot13_decrypted_password))

        # Also return the decrypted password
        return rot13_decrypted_password
    
    # If the user wants to generate a password
    else:
        print(generate_graphic)

        # Get the user's desired password difficulty level
        level = input("Enter a level of difficulty (1, 2, or 3): ")
    
        # List of all ASCII characters
        all_ascii_characters = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',\
                                'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',\
                                    'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_',\
                                        '+', '~', '`', '|', '}', '{', '[', ']', '\\', ':', ';', '?', '>', '<', ',', '.', '/', '-', '=']

        # Main password list, whcih would contain the generated passoword
        password = []

        # Infinite while loop to keep checking if the generated password is compromised or not
        # and if it is compromised, then generate a new password
        while True:
            
            # If the user wants a level 3 password (Strongest)
            if level == '3':

                # Generate a 16 character password
                for i in range(16):
                    
                    # Choose a random character from the list of all ASCII characters
                    x = random.choice(all_ascii_characters)

                    # Adds that random character to the password list
                    password.append(x)
                
                # Check if the password is compromised or not
                y = pwned_api("".join(password))

                # if the password is not compromised, then print the password to the screen
                if y[0] == "No":

                    print("\nNon Compromised STRONG Password: "+ "".join(password) + "\n")

                    break

                # If the password is compromised, then print the number of times it has been compromised
                else:

                    print("".join(password), "has been compromised", y[1], "times")

                    print("Try again...")

                    continue

            # If the user wants a level 2 password (Moderate)
            elif level == '2':

                # Generate a 12 character password
                for i in range(12):
                    
                    # Choose a random character from the list of all ASCII characters
                    x = random.choice(all_ascii_characters)

                    # Adds that random character to the password list
                    password.append(x)

                # Check if the password is compromised or not
                y = pwned_api("".join(password))

                # if the password is not compromised, then print the password to the screen
                if y[0] == "No":

                    print("\nNon Compromised MODERATE Password: "+ "".join(password) + "\n")
                    
                    break
                
                # If the password is compromised, then print the number of times it has been compromised 
                # and generate a new password
                else:

                    print("".join(password), "has been compromised", y[1], "times")

                    print("Try again...")

                    continue
                
            # If the user wants a level 1 password (Simple)
            elif level == '1':

                # Generate a 8 character password
                for i in range(8):
                    
                    # Choose a random character from the list of all ASCII characters
                    x = random.choice(all_ascii_characters)

                    # Adds that random character to the password list
                    password.append(x)
                
                # Check if the password is compromised or not
                y = pwned_api("".join(password))

                # if the password is not compromised, then print the password to the screen
                if y[0] == "No":

                    print("\n Uncompromised SIMPLE Password: "+ "".join(password) + "\n")
                    
                    break

                # if the password is compromised, then print the number of times it has been compromised
                # and generate a new password
                else:
                    print("".join(password), "has been compromised", y[1], "times")

                    print("Try again...")

                    continue

            # If the user enters an invalid input
            else:

                print("Invalid input")

            

                break
                


main(user_choice)

