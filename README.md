# PASSBOLT API PHP EXAMPLE

This repository contains an example of [Passbolt api](https://help.passbolt.com/api) implementation in PHP.

IMPORTANT: The source code provided is not to be used in production as it is. It is only a simplified example of how to
connect to Passbolt API in php and perform operations.

# Examples included:

- index.php : log in, create, retrieve, update, delete passwords and display the request result.

# Requirements:

- A Passbolt server (CE, Pro or Cloud)
- The private key of your user (Download it from the profile section in Passbolt)

# Usage:

The following php libraries are required:

- gnupg
- curl

Command line:

```bash
php ./index.php
```