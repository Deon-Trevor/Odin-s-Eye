#!/usr/bin/python3
from EmailParsers import eml
from EmailParsers import msg


def main(email_header):
    if email_header.endswith(".eml"):
        eml.extract_details(email_header)
    
    elif email_header.endswith(".msg"):
        msg.extract_details(email_header)


if __name__ == "__main__":
    email_header = input("\nEnter the path to the .eml or .msg file:\n> ")

    main(email_header)
