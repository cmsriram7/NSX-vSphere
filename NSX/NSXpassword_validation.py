import re
import argparse
import sys
import getpass

if __name__ == "__main__":
    #
    # Validate if a string is a password:
    #  A valid password consists of 
    #    * 1 upper case character
    #    * 1 lower case character 
    #    * 1 number
    #    * 1 special characters
    #
    
    all_chars = "abcdefghijklmnopqrstuvwxyz"
    all_chars_rev = all_chars[::-1]

    all_nums = "0123456789"
    all_nums_rev = all_nums[::-1]
    not_allowed_chars = ["*", "{", "}", "(", ")", "/", "\\", "'", '"', "\`", "~", "," , ";", ":", ".", "<", ">", "_", "-", "+"]
    not_allowed_chars = "".join(not_allowed_chars)
    password = getpass.getpass("Please enter the password: ") 

    pattern = rf"[" + re.escape(not_allowed_chars) + "]+"

    if re.search(pattern, password):
        print("Password is having invalid characters")
        sys.exit(1)

    if len(password) < 12:
        print("Password invalid")
        sys.exit(1)

    #
    # ?= - Positive lookahead
    # ?: - Non capturing group
    #
    pattern = r"\A(?=(?:[^A-Z]*[A-Z]){1})(?=(?:[^a-z]*[a-z]){1})(?=(?:[^0-9]*[0-9]){1})(?=(?:[^*%$&@!]*[*%$&@!]){1})"
    
    pwd_good = True
    
    print("Checking for upper case, lower case, number and special characters:")
    r = re.search(pattern, password)
    if not r:
        pwd_good = False
    
    print("Checking for repeated character matches:")
    tot_rep = 0
    ch_occur = {}
    for c in password.lower():
        ch_occur[c] = password.lower().count(c.lower())

    for (c, r) in ch_occur.items():
        if r > 1:
            print(c)
            tot_rep += r
    
    diff_chars = len(password) - tot_rep

    print("Total length of the password: {}".format(len(password)))
    print("Total repeated characters: {}".format(tot_rep))
    print("Total non repeated characters: {}".format(diff_chars))

    if diff_chars <= 5:
        pwd_good = False

    pat_nums = r"([0-9]+)"

    for seq in re.findall(pat_nums, password):
        if (seq in all_nums) or (seq in all_nums_rev):
            if len(seq) > 3:
                pwd_good = False

    pat_lets = r"([a-z][A-Z]+)"

    for seq in re.findall(pat_lets, password.lower()):
        if (seq in all_chars) or (seq in all_chars_rev):
            if len(seq) > 3:
                pwd_good = False
    

    if pwd_good:
    	print("Password is valid")
    else:
    	print("Password is invalid")
